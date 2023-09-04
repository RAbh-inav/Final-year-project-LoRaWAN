#include "network-scheduler.h"
#include "lora-device-address.h"
#include "network-server.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/cmac.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include <iostream>
#include <iomanip>
#include <string>
namespace ns3 {
namespace lorawan {

NS_LOG_COMPONENT_DEFINE ("NetworkScheduler");

NS_OBJECT_ENSURE_REGISTERED (NetworkScheduler);

TypeId
NetworkScheduler::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::NetworkScheduler")
    .SetParent<Object> ()
    .AddConstructor<NetworkScheduler> ()
    .AddTraceSource ("ReceiveWindowOpened",
                     "Trace source that is fired when a receive window opportunity happens.",
                     MakeTraceSourceAccessor (&NetworkScheduler::m_receiveWindowOpened),
                     "ns3::Packet::TracedCallback")
    .SetGroupName ("lorawan");
  return tid;
}

NetworkScheduler::NetworkScheduler ():m_nwkkey("0")
{
}

NetworkScheduler::NetworkScheduler (Ptr<NetworkStatus> status,
                                    Ptr<NetworkController> controller) :
  m_status (status),
  m_controller (controller),
  m_nwkkey("0")
{
}

NetworkScheduler::~NetworkScheduler ()
{
}
 
void
NetworkScheduler::Setnetworkkey(std::string nwkkey)
{
m_nwkkey=nwkkey;
}

bool
NetworkScheduler::OnReceivedPacket (Ptr<const Packet> packet)
{
  NS_LOG_FUNCTION (packet);
  std::string receivedMic;
  // Get the current packet's frame counter
  Ptr<Packet> packetCopy = packet->Copy ();
  LorawanMacHeader receivedMacHdr;
  packetCopy->RemoveHeader (receivedMacHdr);
  LoraFrameHeader receivedFrameHdr;
  receivedFrameHdr.SetAsUplink ();
  packetCopy->RemoveHeader (receivedFrameHdr);
  
 
  // Extract the address
   LoraDeviceAddress deviceAddress = receivedFrameHdr.GetAddress ();
    
  LorawanMICTrailer receivedMicTrailer;
 
  packetCopy->RemoveTrailer(receivedMicTrailer);
  uint8_t *msg= new uint8_t[packetCopy->GetSize()];
  packetCopy->CopyData(msg,packetCopy->GetSize());
  uint8_t msglen=packetCopy->GetSize();
  char temp[packetCopy->GetSize()];
  std::memcpy(temp,msg,packetCopy->GetSize());  
  //std::cout <<"temp: "<<temp<<std::endl;
  uint8_t B0[16];
  //uint8_t NwkKey[16];
  uint32_t FCnt;
  LoraDeviceAddress devaddr;
  std::string miccalc;
  FCnt = receivedFrameHdr.GetFCnt();

  devaddr=deviceAddress;
  //NS_LOG_DEBUG("lorawan device address"<<devaddr);
  //NS_LOG_DEBUG("lorawan device address"<<devaddr);

   //receivedMic=9;
  
  //std::string networkkey("dhoni");
  receivedMicTrailer.GenerateB0UL (B0, devaddr, FCnt, msglen);
  miccalc = receivedMicTrailer.CalcMIC (msglen, msg, B0, m_nwkkey);
  receivedMicTrailer.SetMIC (miccalc);
  
  
/*NetworkServer nwksvr;
std::string networkkey1=nwksvr.GetNwrkKey();
std::cout<<"szs"<<networkkey1<<std::endl;
NS_LOG_DEBUG("NETWORK KEY in networkscheduler"<<networkkey);*/

receivedMic=receivedMicTrailer.GetMIC();

std::cout<<"Network key obtained from networkserver "<<m_nwkkey<<std::endl;

NS_LOG_DEBUG("Received MIC:"<<receivedMic);
NS_LOG_DEBUG("Calculated MIC:"<<miccalc);
bool tampornot=false;
  
  if (receivedMic == miccalc)
  {
  
  NS_LOG_DEBUG("PACKET HAS NOT BEEN TAMPERED");
  tampornot=true;
  }
  else
  {
  
  NS_LOG_DEBUG("PACKETS HAS BEEN TAMPERED");
  m_controller->OnFailedReply(m_status->GetEndDeviceStatus(deviceAddress));

  }
  
  // Need to decide whether to schedule a receive window
  if (!m_status->GetEndDeviceStatus (packet)->HasReceiveWindowOpportunityScheduled ())
  {
    

    // Schedule OnReceiveWindowOpportunity event
    m_status->GetEndDeviceStatus (packet)->SetReceiveWindowOpportunity (
      Simulator::Schedule (Seconds (1),
                           &NetworkScheduler::OnReceiveWindowOpportunity,
                           this,
                           deviceAddress,
                           1)); // This will be the first receive window
  }
  return tampornot;
  
}

void
NetworkScheduler::OnReceiveWindowOpportunity (LoraDeviceAddress deviceAddress, int window)
{
  NS_LOG_FUNCTION (deviceAddress);

  NS_LOG_DEBUG ("Opening receive window number " << window << " for device "
                                                 << deviceAddress);

  // Check whether we can send a reply to the device, again by using
  // NetworkStatus
  Address gwAddress = m_status->GetBestGatewayForDevice (deviceAddress, window);

  if (gwAddress == Address () && window == 1)
    {
      NS_LOG_DEBUG ("No suitable gateway found for first window.");

      // No suitable GW was found, but there's still hope to find one for the
      // second window.
      // Schedule another OnReceiveWindowOpportunity event
      m_status->GetEndDeviceStatus (deviceAddress)->SetReceiveWindowOpportunity (
        Simulator::Schedule (Seconds (1),
                             &NetworkScheduler::OnReceiveWindowOpportunity,
                             this,
                             deviceAddress,
                             2));     // This will be the second receive window
    }
  else if (gwAddress == Address () && window == 2)
    {
      // No suitable GW was found and this was our last opportunity
      // Simply give up.
      NS_LOG_DEBUG ("Giving up on reply: no suitable gateway was found " <<
                   "on the second receive window");

      // Reset the reply
      // XXX Should we reset it here or keep it for the next opportunity?
      m_status->GetEndDeviceStatus (deviceAddress)->RemoveReceiveWindowOpportunity();
      m_status->GetEndDeviceStatus (deviceAddress)->InitializeReply ();
    }
  else
    {
      // A gateway was found

      NS_LOG_DEBUG ("Found available gateway with address: " << gwAddress);

      m_controller->BeforeSendingReply (m_status->GetEndDeviceStatus
                                          (deviceAddress));

      // Check whether this device needs a response by querying m_status
      bool needsReply = m_status->NeedsReply (deviceAddress);

      if (needsReply)
        {
          NS_LOG_INFO ("A reply is needed");

          // Send the reply through that gateway
          m_status->SendThroughGateway (m_status->GetReplyForDevice
                                          (deviceAddress, window),
                                        gwAddress);

          // Reset the reply
          m_status->GetEndDeviceStatus (deviceAddress)->RemoveReceiveWindowOpportunity();
          m_status->GetEndDeviceStatus (deviceAddress)->InitializeReply ();
        }
    }
}
}
}
