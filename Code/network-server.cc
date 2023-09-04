/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Davide Magrin <magrinda@dei.unipd.it>
 *          Martina Capuzzo <capuzzom@dei.unipd.it>
 */

#include "ns3/network-server.h"
#include "ns3/net-device.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/packet.h"
#include "ns3/lorawan-mac-header.h"
#include "ns3/lora-frame-header.h"
#include "ns3/lora-device-address.h"
#include "ns3/network-status.h"
#include "ns3/lora-frame-header.h"
#include "ns3/lorawan-mic-trailer.h"
#include "ns3/node-container.h"
#include "ns3/class-a-end-device-lorawan-mac.h"
#include "ns3/mac-command.h"


#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hrtimer.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/chacha.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include <iostream>
#include <string>


namespace ns3 {
namespace lorawan {

NS_LOG_COMPONENT_DEFINE ("NetworkServer");

NS_OBJECT_ENSURE_REGISTERED (NetworkServer);

TypeId
NetworkServer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::NetworkServer")
    .SetParent<Application> ()
    .AddConstructor<NetworkServer> ()
    .AddTraceSource ("ReceivedPacket",
                     "Trace source that is fired when a packet arrives at the Network Server",
                     MakeTraceSourceAccessor (&NetworkServer::m_receivedPacket),
                     "ns3::Packet::TracedCallback")
    .SetGroupName ("lorawan");
  return tid;
}

NetworkServer::NetworkServer () :
  m_status (Create<NetworkStatus> ()),
  m_controller (Create<NetworkController> (m_status)),
  m_scheduler (Create<NetworkScheduler> (m_status, m_controller)),
  m_appkey("0"),
  m_appIV("0"),
  m_nwkkey("012")
{
  NS_LOG_FUNCTION_NOARGS ();
}

NetworkServer::~NetworkServer ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

void
NetworkServer::StartApplication (void)
{
  NS_LOG_FUNCTION_NOARGS ();
}

void
NetworkServer::StopApplication (void)
{
  NS_LOG_FUNCTION_NOARGS ();
}

void
NetworkServer::AddGateway (Ptr<Node> gateway, Ptr<NetDevice> netDevice)
{
  NS_LOG_FUNCTION (this << gateway);

  // Get the PointToPointNetDevice
  Ptr<PointToPointNetDevice> p2pNetDevice;
  for (uint32_t i = 0; i < gateway->GetNDevices (); i++)
    {
      p2pNetDevice = gateway->GetDevice (i)->GetObject<PointToPointNetDevice> ();
      if (p2pNetDevice != 0)
        {
          // We found a p2pNetDevice on the gateway
          break;
        }
    }

  // Get the gateway's LoRa MAC layer (assumes gateway's MAC is configured as first device)
  Ptr<GatewayLorawanMac> gwMac = gateway->GetDevice (0)->GetObject<LoraNetDevice> ()->
    GetMac ()->GetObject<GatewayLorawanMac> ();
  NS_ASSERT (gwMac != 0);

  // Get the Address
  Address gatewayAddress = p2pNetDevice->GetAddress ();

  // Create new gatewayStatus
  Ptr<GatewayStatus> gwStatus = Create<GatewayStatus> (gatewayAddress,
                                                       netDevice,
                                                       gwMac);

  m_status->AddGateway (gatewayAddress, gwStatus);
}

void
NetworkServer::AddNodes (NodeContainer nodes)
{
  NS_LOG_FUNCTION_NOARGS ();

  // For each node in the container, call the function to add that single node
  NodeContainer::Iterator it;
  for (it = nodes.Begin (); it != nodes.End (); it++)
    {
      AddNode (*it);
    }
}

void
NetworkServer::AddNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);

  // Get the LoraNetDevice
  Ptr<LoraNetDevice> loraNetDevice;
  for (uint32_t i = 0; i < node->GetNDevices (); i++)
    {
      loraNetDevice = node->GetDevice (i)->GetObject<LoraNetDevice> ();
      if (loraNetDevice != 0)
        {
          // We found a LoraNetDevice on the node
          break;
        }
    }

  // Get the MAC
  Ptr<ClassAEndDeviceLorawanMac> edLorawanMac =
    loraNetDevice->GetMac ()->GetObject<ClassAEndDeviceLorawanMac> ();

  // Update the NetworkStatus about the existence of this node
  m_status->AddNode (edLorawanMac);
}


bool
NetworkServer::Receive (Ptr<NetDevice> device, Ptr<const Packet> packet,
                        uint16_t protocol, const Address& address)
{
using namespace CryptoPP;
AutoSeededRandomPool prng;
  NS_LOG_FUNCTION (this << packet << protocol << address);
  
  const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.3 * 1000 * 1000 * 1000;

  // Create a copy of the packet
  Ptr<Packet> myPacket = packet->Copy ();
  LorawanMacHeader receivedMacHdr;
  myPacket->RemoveHeader (receivedMacHdr);
  LoraFrameHeader receivedFrameHdr;
  myPacket->RemoveHeader (receivedFrameHdr);
  //uint16_t framecount=receivedFrameHdr.GetFCnt();
 //std::string count=std::to_string(framecount);
 //std::cout<<"framecount"<<count<<std::endl;
  
  
  //std::cout<<"nwkkey obtained:"<<m_nwkkey<<std::endl;
  

  // Fire the trace source
  m_receivedPacket (packet);
  
  m_scheduler->Setnetworkkey(m_nwkkey);
  
  
  LorawanMICTrailer receivedMicTrailer;
  myPacket->RemoveTrailer(receivedMicTrailer);
  uint8_t *buffer= new uint8_t[myPacket->GetSize()];
  myPacket->CopyData(buffer,packet->GetSize());
  char temp[myPacket->GetSize()];
  std::memcpy(temp,buffer,myPacket->GetSize());
  std::string output=temp;
  std::cout<<output.size()<<std::endl;
  NS_LOG_DEBUG("Data in network server:"<< output);
  output.resize(myPacket->GetSize());
  //std::cout<<output<<std::endl;
  
  //std::cout<<"string is"<<output<<std::endl;
  //std::string output=temp;
  std::cout<<"packetsize is"<<myPacket->GetSize()<<std::endl;
  
  
   //byte passwordbyte[16];
   byte passwordbyte[32];
   byte ivbyte[8];
   //byte ivbyte[16];
  
  
  memset(passwordbyte,0,sizeof(passwordbyte));
  memcpy(passwordbyte,m_appkey.data(),m_appkey.size());
  
  memset(ivbyte,0,sizeof(ivbyte));
  memcpy(ivbyte,m_appIV.data(),m_appIV.size());
  const byte * iv2=&ivbyte[0];
  
const AlgorithmParameters params= MakeParameters(Name::Rounds(),8)(Name::IV(),ConstByteArrayParameter(iv2,8));
  
  std::string recovered;
  // Inform the scheduler of the newly arrived packet
  bool decrypt=m_scheduler->OnReceivedPacket (packet);
  std::cout<<"Key:"<<m_appkey<<std::endl;
  std::cout<<"IV:"<<m_appIV<<std::endl;
  std::cout<<"Integrity there(1) or not(0):"<<decrypt<<std::endl;
  if(decrypt)
  {
  try
    {
        ChaCha::Decryption d;
        d.SetKey(passwordbyte, sizeof(passwordbyte), params);
        
        //CTR_Mode< AES >::Encryption d;
       // d.SetKeyWithIV(passwordbyte, sizeof(passwordbyte), ivbyte);
        
 
        StringSource s(output, true, 
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
            ); // StringSource
            
            
             /*const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(d).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            d.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << d.AlgorithmName() << "Decryption benchmarks..." << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    std::cout << "  " << elapsedTimeInSeconds << " seconds passed" << std::endl;
    std::cout << "  " << (word64) bytes << " bytes processed" << std::endl;

*/

        std::cout <<  "Recovered Text:"<<recovered << std::endl;
        std::cout << "Recovered Text Size(" << recovered.size() << " bytes)" <<std::endl;
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
  
  }

  // Inform the status of the newly arrived packet
  m_status->OnReceivedPacket (packet, address);

  // Inform the controller of the newly arrived packet
  m_controller->OnNewPacket (packet);

  return true;
}

void
NetworkServer::SetAppliKey(std::string appkey)
{

m_appkey=appkey;
NS_LOG_DEBUG("APPKEY IS "<<m_appkey);
}
void
NetworkServer::SetAppliIV(std::string appiv)
{

m_appIV=appiv;
NS_LOG_DEBUG("APPIV IS "<<m_appIV);
}

void
NetworkServer::SetNwrkKey(std::string nwkkey)
{

m_nwkkey=nwkkey;
NS_LOG_DEBUG("NWKKEY IS "<<m_nwkkey);

}
std::string
NetworkServer::GetNwrkKey(void)
{
NS_LOG_DEBUG("NETWORK KEY OBTAINED"<<m_nwkkey);

return m_nwkkey;
}


void
NetworkServer::AddComponent (Ptr<NetworkControllerComponent> component)
{
  NS_LOG_FUNCTION (this << component);

  m_controller->Install (component);
}

Ptr<NetworkStatus>
NetworkServer::GetNetworkStatus (void)
{
  return m_status;
}

}
}
