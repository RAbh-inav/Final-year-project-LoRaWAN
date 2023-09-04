#include "ns3/forwarder-helper.h"
#include "ns3/lorawan-mic-trailer.h"
#include "ns3/network-server-helper.h"
#include "ns3/network-server.h"
#include "ns3/mobility-helper.h"
#include "ns3/lora-phy-helper.h"
#include "ns3/lora-interference-helper.h"
#include "ns3/lorawan-mac-helper.h"
#include "ns3/lora-helper.h"
#include "ns3/one-shot-sender-helper.h"
#include "ns3/one-shot-sender.h"
#include "ns3/periodic-sender-helper.h"
#include "ns3/periodic-sender.h"
#include "ns3/lorawan-mic-trailer.h"
#include "ns3/netanim-module.h"
#include "ns3/lora-frame-header.h"
#include "ns3/basic-energy-source-helper.h"
#include "ns3/lora-radio-energy-model-helper.h"
#include "ns3/file-helper.h"
#include "ns3/names.h"

#include "cryptopp/filters.h"
#include "cryptopp/chacha.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hrtimer.h"
#include <iostream>
#include <string>

using namespace ns3;
using namespace lorawan;
/*std::string fcnt1="0";
void
OnPhySentPacket (Ptr<const Packet> packet, uint32_t index)
{
  Ptr<Packet> packetCopy = packet->Copy();

  LorawanMacHeader mHdr;
  packetCopy->RemoveHeader (mHdr);
  LoraFrameHeader fHdr;
  packetCopy->RemoveHeader (fHdr);

  std::cout<<"Sent a packet with Frame Counter " <<    fHdr.GetFCnt()<<std::endl;
   //uint16_t Fcnt=fHdr.GetFCnt()+1;
  //std::string fcnt1=std::to_string(Fcnt);
  
  // NS_LOG_DEBUG ("MAC Header:");
  // NS_LOG_DEBUG (mHdr);
  // NS_LOG_DEBUG ("Frame Header:");
  // NS_LOG_DEBUG (fHdr);
}*/


int main (int argc, char* argv[])

{
const double runTimeInSeconds = 3.0;
const double cpuFreq = 230*  1000 * 1000;

using namespace CryptoPP;
  // Logging
  //////////LOG_LEVEL_ALL);
  LogComponentEnable ("OneShotSenderHelper", LOG_LEVEL_ALL);
  LogComponentEnable ("OneShotSender", LOG_LEVEL_ALL);
  LogComponentEnable ("NetworkServer", LOG_LEVEL_ALL);
   LogComponentEnable("LoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable("NetworkScheduler", LOG_LEVEL_ALL);
  LogComponentEnable ("EndDeviceLorawanMac", LOG_LEVEL_ALL);
  //LogComponentEnable ("LorawanMICTrailer", LOG_LEVEL_ALL);
  //LogComponentEnableAll (LOG_PREFIX_TIME);
  /*LogComponentEnable ("PeriodicSender", LOG_LEVEL_ALL);
  LogComponentEnable ("PeriodicSenderHelper", LOG_LEVEL_ALL);
  LogComponentEnable("LoraHelper", LOG_LEVEL_ALL);
  LogComponentEnable("LoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable("LoraChannel", LOG_LEVEL_ALL);
  LogComponentEnable("EndDeviceLoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable ("GatewayLorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable ("EndDeviceLorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable ("ClassAEndDeviceLorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable("LorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable("LoraHelper", LOG_LEVEL_ALL);
  LogComponentEnable("LoraPhyHelper", LOG_LEVEL_ALL);
 LogComponentEnable("LorawanMacHelper", LOG_LEVEL_ALL);
 LogComponentEnable ("OneShotSenderHelper", LOG_LEVEL_ALL);
 LogComponentEnable ("OneShotSender", LOG_LEVEL_ALL);
  LogComponentEnable ("NetworkServer", LOG_LEVEL_ALL);
  LogComponentEnable ("NetworkServerHelper", LOG_LEVEL_ALL);
  LogComponentEnable ("GatewayLorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable("LoraFrameHeader", LOG_LEVEL_ALL);
  LogComponentEnable("LorawanMacHeader", LOG_LEVEL_ALL);
  LogComponentEnable("GatewayLoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable("LoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable("LoraChannel", LOG_LEVEL_ALL);
  LogComponentEnable("EndDeviceLoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable("LogicalLoraChannelHelper", LOG_LEVEL_ALL);
  LogComponentEnable ("EndDeviceLorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable ("ClassAEndDeviceLorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable ("OneShotSender", LOG_LEVEL_ALL);
  LogComponentEnable("PointToPointNetDevice", LOG_LEVEL_ALL);
  LogComponentEnable("PointToPointChannel", LOG_LEVEL_ALL);
  LogComponentEnable ("Forwarder", LOG_LEVEL_ALL);
  LogComponentEnable ("GatewayStatus", LOG_LEVEL_ALL);
  LogComponentEnable ("LoraDeviceAddress", LOG_LEVEL_ALL);
  LogComponentEnable ("LoraDeviceAddressGenerator", LOG_LEVEL_ALL);
  LogComponentEnable("LoraInterferenceHelper", LOG_LEVEL_ALL);
  LogComponentEnable("LorawanMac", LOG_LEVEL_ALL);
  LogComponentEnable("LogicalLoraChannel", LOG_LEVEL_ALL);
  LogComponentEnable("LoraHelper", LOG_LEVEL_ALL);
  LogComponentEnable("LoraPhyHelper", LOG_LEVEL_ALL);
  LogComponentEnable("LorawanMacHelper", LOG_LEVEL_ALL);
  LogComponentEnable("NetworkScheduler", LOG_LEVEL_ALL);
  LogComponentEnable("NetworkStatus", LOG_LEVEL_ALL);
  LogComponentEnable("NetworkController", LOG_LEVEL_ALL);
  LogComponentEnable ("EndDeviceStatus", LOG_LEVEL_ALL);
  LogComponentEnable ("Channel", LOG_LEVEL_ALL);
 LogComponentEnable ("OneShotSenderHelper", LOG_LEVEL_ALL);
  LogComponentEnable ("SimpleGatewayLoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable ("SimpleEndDeviceLoraPhy", LOG_LEVEL_ALL);
  LogComponentEnable ("NetworkControllerComponent", LOG_LEVEL_ALL);
  LogComponentEnable ("NetworkServerHelper", LOG_LEVEL_ALL);
  LogComponentEnable ("LoraNetDevice", LOG_LEVEL_ALL);*/

  LogComponentEnableAll (LOG_PREFIX_FUNC);
  LogComponentEnableAll (LOG_PREFIX_NODE);
  LogComponentEnableAll (LOG_PREFIX_TIME);
  
  
   LoraInterferenceHelper::collisionMatrix = LoraInterferenceHelper::ALOHA;

  
  // Create a simple wireless channel
  ///////////////////////////////////

  Ptr<LogDistancePropagationLossModel> loss = CreateObject<LogDistancePropagationLossModel> ();
  loss->SetPathLossExponent (3.76);
  loss->SetReference (1, 7.7);

  Ptr<PropagationDelayModel> delay = CreateObject<ConstantSpeedPropagationDelayModel> ();

  Ptr<LoraChannel> channel = CreateObject<LoraChannel> (loss, delay);

  // Helpers
  //////////

  // Create the LoraPhyHelper
  LoraPhyHelper phyHelper = LoraPhyHelper ();
  phyHelper.SetChannel (channel);

  // Create the LorawanMacHelper
  LorawanMacHelper macHelper = LorawanMacHelper ();

  // Create the LoraHelper
  LoraHelper helper = LoraHelper ();
  helper.EnablePacketTracking ();
  //Create Mobility Helper
  MobilityHelper mobilityEd, mobilityGw,mobilityNs;
  
  // End Device mobility
  Ptr<ListPositionAllocator> positionAllocEd = CreateObject<ListPositionAllocator> ();
  positionAllocEd->Add (Vector (1000.0, 2000.0, 0.0));
  positionAllocEd->Add (Vector (1000.0, 4000.0, 0.0));
 // mobilityEd.SetPositionAllocator ("ns3::UniformDiscPositionAllocator", "rho", DoubleValue (1000), "X", DoubleValue (0.0), "Y", DoubleValue (0.0));
  mobilityEd.SetPositionAllocator (positionAllocEd);
  mobilityEd.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  
  // Gateway mobility
  Ptr<ListPositionAllocator> positionAllocGw = CreateObject<ListPositionAllocator> ();
  positionAllocGw->Add (Vector (3000.0, 3000.0, 0.0));
  mobilityGw.SetPositionAllocator (positionAllocGw);
  mobilityGw.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  
  // Network Server mobility
  Ptr<ListPositionAllocator> positionAllocNs = CreateObject<ListPositionAllocator> ();
  positionAllocNs->Add (Vector (5000.0,3000.0, 0.0));
  mobilityNs.SetPositionAllocator (positionAllocNs);
  mobilityNs.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  
  // Create EDs
  /////////////

  NodeContainer endDevices;
  endDevices.Create (200);
  mobilityEd.Install (endDevices);

  // Create a LoraDeviceAddressGenerator
  uint8_t nwkId = 54;
  uint32_t nwkAddr = 1864;
  Ptr<LoraDeviceAddressGenerator> addrGen = CreateObject<LoraDeviceAddressGenerator> (nwkId,nwkAddr);

  // Create the LoraNetDevices of the end devices
  phyHelper.SetDeviceType (LoraPhyHelper::ED);
  macHelper.SetDeviceType (LorawanMacHelper::ED_A);
  macHelper.SetAddressGenerator (addrGen);
  macHelper.SetRegion (LorawanMacHelper::ALOHA);
  macHelper.Set("DataRate", UintegerValue(5));
  //macHelper.Set("DataRate", UintegerValue(5));
  NetDeviceContainer endDevicesNetDevices=helper.Install (phyHelper, macHelper, endDevices);
/* for (NodeContainer::Iterator j = endDevices.Begin (); j != endDevices.End (); ++j)
    {
      Ptr<Node> node = *j;
      Ptr<LoraNetDevice> loraNetDevice = node->GetDevice (0)->GetObject<LoraNetDevice> ();
      Ptr<LoraPhy> phy = loraNetDevice->GetPhy ();
      Ptr<EndDeviceLorawanMac> mac = loraNetDevice->GetMac ()->GetObject<EndDeviceLorawanMac> ();
      phy->TraceConnectWithoutContext("StartSending", MakeCallback(&OnPhySentPacket));
     
    }*/
    



//message

std::string msg1 ="Abhinav";
LoraFrameHeader frameheader;
uint32_t DevAddr=0;
DevAddr |= (nwkAddr | nwkId);
uint16_t FCnt=frameheader.GetFCnt();

uint8_t A[16];
A[0]=0x01;
A[1]=0X00;
A[2]=0X00;
A[3]=0X00;
A[4]=0X00;
A[5]=0X00;
A[6] = (uint8_t)(DevAddr >> 24);
A[7] = (uint8_t)((DevAddr & 0x00ff0000) >> 16);
A[8] = (uint8_t)((DevAddr & 0x0000ff00) >> 8);
A[9] = (uint8_t)(DevAddr & 0x000000ff);
A[10] = (uint8_t)(FCnt >> 24);
A[11] = (uint8_t)((FCnt & 0x00ff0000) >> 16);
A[12] = (uint8_t)((FCnt & 0x0000ff00) >> 8);
A[13] = (uint8_t)(FCnt & 0x000000ff);
A[14]=0X00;
A[15]=msg1.size()/16;
char* a_dup=(char*)A;
std::string a1=a_dup;

std::string msg=msg1;
//std::cout<<a1<<std::endl;
//std::cout<<msg<<std::endl;

    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));
    std::string cipher,recovered;
    std::string cipher1,cipher2;
    
     byte key[32];
    byte Nkey[32];
     byte iv[8];

    std::string appkey("sgggsffscdcadada");
    memset(key,0,sizeof(key));
    std::cout << "Key Size (" << appkey.size()<< " bytes)" <<std::endl;
    memcpy(key,appkey.data(),appkey.size());
    std::cout<<"key is "<<appkey<<std::endl;
    std::cout << "Key :";
     encoder.Put(key, sizeof(key));
    encoder.MessageEnd();
    std::cout << std::endl;
  
    
    std::string appiv;
    appiv="00000001";
   
   memset(iv,0,sizeof(iv));
    memcpy(iv,appiv.data(),appiv.size());
    std::cout<<"Iv is "<<appiv<<std::endl;
    std::cout << "Iv Size (" << appiv.size()<< " bytes)" <<std::endl;
    //std::cout << "Iv :";
    //encoder.Put(iv, sizeof(iv));
   // encoder.MessageEnd();
    //std::cout << std::endl;
   // iv[7]=01;
   // std::cout<<"iv is" <<unsigned(iv[7]) <<std::endl;
    const byte *iv2=&iv[0];
    
    
    const AlgorithmParameters params= MakeParameters(Name::Rounds(),8)(Name::IV(),ConstByteArrayParameter(iv2,8));


try
    {
        ChaCha::Encryption e;
        e.SetKey(key, sizeof(key),params);
        StringSource s(msg, true, 
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
        
        
    
    
        //std::cout<<"elapsed time"<<elapsedTimeInSeconds;
    /* const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(e).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks += 2;
        for (; i<blocks; i++)
            e.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        //std::cout<<"elapsed time: "<<elapsedTimeInSeconds<<std::endl;
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << e.AlgorithmName() << " benchmarks..." << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    std::cout << "  " << elapsedTimeInSeconds << " seconds passed" << std::endl;
    std::cout << "  " << (word64) bytes << " bytes processed" << std::endl;
*/
    }
    
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
      
    }
   
    
   
    //CTR_Mode<AES>::Encryption ctrEncryption;
    //ctrEncryption.SetKeyWithIV(key, sizeof(key), iv);

    
    
   
    std::cout << "plain text: " << msg << std::endl;
    std::cout << "Plain Text Size(" << msg.size() << " bytes)" <<std::endl;
    std::cout<<"cipher payload: "<<cipher<<std::endl;
    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;
    std::cout << "Cipher Text Size(" << cipher.size() << " bytes)" <<std::endl;
    
    
  /*  try
    {
        CTR_Mode< AES >::Encryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

        StringSource s(cipher, true, 
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        std::cout << "recovered text: " << recovered << std::endl;
        std::cout << "Recovered Text Size(" << recovered.size() << " bytes)" <<std::endl;
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }*/
   
    
   char const *cword=(cipher).c_str();
   uint8_t *data= new uint8_t[cipher.size()];
   std::memcpy(data,cword,cipher.size());
    //std::cout<<"size of cipher"<<sizeof(cword)<<std::endl;
   
   std::string nwkkey("dhoni");
    
    std::cout<<"Network key is "<<nwkkey<<std::endl;
   
  
   

  // Set message type (Default is unconfirmed)
  Ptr<LorawanMac> edMac1 = endDevices.Get (0)->GetDevice (0)->GetObject<LoraNetDevice> ()->GetMac ();
  Ptr<ClassAEndDeviceLorawanMac> edLorawanMac1 = edMac1->GetObject<ClassAEndDeviceLorawanMac> ();
  edLorawanMac1->SetMType (LorawanMacHeader::UNCONFIRMED_DATA_UP);
  
  Ptr<LorawanMac> edMac2 = endDevices.Get (1)->GetDevice (0)->GetObject<LoraNetDevice> ()->GetMac ();
  Ptr<ClassAEndDeviceLorawanMac> edLorawanMac2 = edMac2->GetObject<ClassAEndDeviceLorawanMac> ();
  edLorawanMac2->SetMType (LorawanMacHeader::UNCONFIRMED_DATA_UP);


  // Install applications in EDs
 // uint8_t const *buffer=reinterpret_cast<const uint8_t*>("hello");
 /* OneShotSenderHelper oneShotHelper = OneShotSenderHelper ();
  oneShotHelper.SetSendTime (Seconds (4));
  oneShotHelper.SetPacketSize(cipher.size());
  oneShotHelper.SetPayload(data);
  oneShotHelper.SetNetworkkey(nwkkey);
  oneShotHelper.Install (endDevices.Get(1));*/
  
  
  PeriodicSenderHelper appHelper = PeriodicSenderHelper ();
  appHelper.SetPeriod (Seconds (600));
  appHelper.SetPacketSize(cipher.size());
  appHelper.SetPayload(data);
  appHelper.SetNetworkkey(nwkkey);
  ApplicationContainer appContainer = appHelper.Install (endDevices);
  appContainer.Start (Seconds (0));
  appContainer.Stop (Seconds (600));
  
  
  
  

  ////////////////
  // Create GWs //
  ////////////////

  NodeContainer gateways;
  gateways.Create (1);
  mobilityGw.Install (gateways);
  
  // Create the LoraNetDevices of the gateways
  phyHelper.SetDeviceType (LoraPhyHelper::GW);
  macHelper.SetDeviceType (LorawanMacHelper::GW);
  helper.Install (phyHelper, macHelper, gateways);

  // Set spreading factors up
 // macHelper.SetSpreadingFactorsUp (endDevices, gateways, channel);

  ////////////
  // Create NS
  ////////////

  NodeContainer networkServers;
  networkServers.Create (1);
  mobilityNs.Install (networkServers);

  // Install the NetworkServer application on the network server
  NetworkServerHelper networkServerHelper;
  networkServerHelper.SetGateways (gateways);
  networkServerHelper.SetEndDevices (endDevices);
  networkServerHelper.SetAppKey(appkey);
  networkServerHelper.SetAppIV(appiv);
  networkServerHelper.SetNwkKey(nwkkey);
  networkServerHelper.Install (networkServers);
  


    //NetworkServer networkserver;
    //outbuf=networkserver.GetData();
    //std::cout<<"output buffer"<<outbuf<<std::endl;
    
    
    
  // Install the Forwarder application on the gateways
  ForwarderHelper forwarderHelper;
  forwarderHelper.Install (gateways);
  
  //Dummy node for animation alignment
  NodeContainer Dummy;
  Dummy.Create(1);
  
  //NetAnim Animation
  AnimationInterface anim("Lorawansecondreview2.xml");
  anim.UpdateNodeDescription(endDevices.Get(0), "End Device 1");
  anim.UpdateNodeDescription(endDevices.Get(1), "End Device 2");
  anim.UpdateNodeDescription(gateways.Get(0), "Gateway");
  anim.UpdateNodeDescription(networkServers.Get(0), "Network Server");
  anim.SetConstantPosition(Dummy.Get(0),5550.0,3550.0);
  anim.UpdateNodeDescription(Dummy.Get(0), "");
  
  
  /*BasicEnergySourceHelper basicSourceHelper;
  LoraRadioEnergyModelHelper radioEnergyHelper;

  // configure energy source
  basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (10000)); // Energy in J
  basicSourceHelper.Set ("BasicEnergySupplyVoltageV", DoubleValue (3.3));

  radioEnergyHelper.Set ("StandbyCurrentA", DoubleValue (0.0014));
  radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.028));
  radioEnergyHelper.Set ("SleepCurrentA", DoubleValue (0.0000015));
  radioEnergyHelper.Set ("RxCurrentA", DoubleValue (0.0112));

  radioEnergyHelper.SetTxCurrentModel ("ns3::ConstantLoraTxCurrentModel",
                                       "TxCurrent", DoubleValue (0.028));

  // install source on EDs' nodes
  EnergySourceContainer sources = basicSourceHelper.Install (endDevices);
  Names::Add ("/Names/EnergySource", sources.Get (0));

  // install device model
  DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install
      (endDevicesNetDevices, sources);

  /**************
   * Get output *
   **************/
  /*FileHelper fileHelper;
  fileHelper.ConfigureFile ("battery-level3", FileAggregator::SPACE_SEPARATED);
  fileHelper.WriteProbe ("ns3::DoubleProbe", "/Names/EnergySource/RemainingEnergy", "Output");*/
   
  // Start simulation
  Simulator::Stop (Seconds (1000));
  Simulator::Run ();
  
  Simulator::Destroy ();
  
LoraPacketTracker &tracker = helper.GetPacketTracker ();
  std::cout<<"Printing total sent MAC-layer packets "<<std::endl;
  std::cout << tracker.CountMacPacketsGlobally (Seconds (0), Seconds (10)) << std::endl;
  return 0;
}
