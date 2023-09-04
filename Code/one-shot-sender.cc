/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 University of Padova
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
 * Author: Davide Magrin <magrinda@dei.unipd.it>
 */

#include "ns3/one-shot-sender.h"
#include "ns3/class-a-end-device-lorawan-mac.h"
#include "ns3/pointer.h"
#include "ns3/log.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/lora-net-device.h"

namespace ns3 {
namespace lorawan {


NS_LOG_COMPONENT_DEFINE ("OneShotSender");

NS_OBJECT_ENSURE_REGISTERED (OneShotSender);


TypeId
OneShotSender::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OneShotSender")
    .SetParent<Application> ()
    .AddConstructor<OneShotSender> ()
    .SetGroupName ("lorawan");
  return tid;
}

OneShotSender::OneShotSender ():pacsize(0),
                                buff(reinterpret_cast<const uint8_t*>("x")),
                                m_nwkkey("0")
{
  NS_LOG_FUNCTION_NOARGS ();
}

OneShotSender::OneShotSender (Time sendTime)
  : m_sendTime (sendTime)
{
  NS_LOG_FUNCTION_NOARGS ();
}

OneShotSender::~OneShotSender ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

void
OneShotSender::SetSendTime (Time sendTime)
{
  NS_LOG_FUNCTION (this << sendTime);

  m_sendTime = sendTime;
}

void 
OneShotSender::SetPacketSize(uint8_t size)
{
pacsize=size;
}

void 
OneShotSender::SetNwrkkey(std::string nwkkey)
{
m_nwkkey=nwkkey;
NS_LOG_DEBUG("NETWORK KEY in one shot sender "<<m_nwkkey);
}

void 
OneShotSender::SetPayload(uint8_t const *buffer)
{
buff=buffer;
}

void
OneShotSender::SendPacket (void)
{
  NS_LOG_FUNCTION (this);
  
  uint8_t const *m_buff=buff;
  uint8_t m_pacsize=pacsize;
 // NS_LOG_DEBUG(unsigned(pacsize));
  // Create and send a new packet
  Ptr<Packet> packet = Create<Packet> (m_buff,m_pacsize);
  m_mac->SetNWKkey(m_nwkkey);
  m_mac->Send (packet);
  NS_LOG_DEBUG("Sent a packet of size "<<unsigned(m_pacsize));
  //packet->GetSize());
}

void
OneShotSender::StartApplication (void)
{
  NS_LOG_FUNCTION (this);

  // Make sure we have a MAC layer
  if (m_mac == 0)
    {
      // Assumes there's only one device
      Ptr<LoraNetDevice> loraNetDevice = m_node->GetDevice (0)->GetObject<LoraNetDevice> ();

      m_mac = loraNetDevice->GetMac ();
      NS_ASSERT (m_mac != 0);
    }

  // Schedule the next SendPacket event
  Simulator::Cancel (m_sendEvent);
  m_sendEvent = Simulator::Schedule (m_sendTime, &OneShotSender::SendPacket , this);
}

void
OneShotSender::StopApplication (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  Simulator::Cancel (m_sendEvent);
}
}
}
