//********************************************************************************************
//
// File : enc28j60.c Microchip ENC28J60 Ethernet Interface Driver
//
//********************************************************************************************
//
// Copyright (C) 2007
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation; either version 2 of the License, or (at your option) any later
// version.
// This program is distributed in the hope that it will be useful, but
//
// WITHOUT ANY WARRANTY;
//
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc., 51
// Franklin St, Fifth Floor, Boston, MA 02110, USA
//
// http://www.gnu.de/gpl-ger.html
//
//********************************************************************************************
#include "enc28j60.h"
#include "main.h"
#include "util.h"

extern SPI_HandleTypeDef hspi1;

void _delay_us(int t) {
	while (t--)
		asm("nop");
}

//struct enc28j60_flag
//{
//	unsigned rx_buffer_is_free:1;
//	unsigned unuse:7;
//}enc28j60_flag;
unsigned char Enc28j60Bank;
unsigned short next_packet_ptr;
const unsigned char avr_mac[MAC_ADDRESS_SIZE] = { NET_MAC };
//*******************************************************************************************
//
// Function : enc28j60ReadOp
//
//*******************************************************************************************
unsigned char enc28j60ReadOp(unsigned char op, unsigned char address) {
//	// activate CS
//	CSACTIVE;
//	// issue read command
//	SPDR = op | (address & ADDR_MASK);
//	waitspi();
//	// read data
//	SPDR = 0x00;
//	waitspi();
//	// do dummy read if needed (for mac and mii, see datasheet page 29)
//	if(address & 0x80)
//	{
//		SPDR = 0x00;
//		waitspi();
//	}
//	// release CS
//	CSPASSIVE;
//	return(SPDR);

	CSACTIVE;
	uint8_t rx = 0, tx = op | (address & ADDR_MASK);
	HAL_SPI_Transmit(&hspi1, (uint8_t*) &tx, 1, 100);
	HAL_SPI_Receive(&hspi1, (uint8_t*) &rx, 1, 100);
	if (address & 0x80) {
		HAL_SPI_Receive(&hspi1, (uint8_t*) &rx, 1, 100);
	}
	CSPASSIVE;
	return rx;
}
//*******************************************************************************************
//
// Function : icmp_send_request
// Description : Send ARP request packet to destination.
//
//*******************************************************************************************
void enc28j60WriteOp(unsigned char op, unsigned char address,
		unsigned char data) {
//	CSACTIVE;
//	// issue write command
//	SPDR = op | (address & ADDR_MASK);
//	waitspi();
//	// write data
//	SPDR = data;
//	waitspi();
//	CSPASSIVE;
	CSACTIVE;
	uint8_t tx = op | (address & ADDR_MASK);
	HAL_SPI_Transmit(&hspi1, (uint8_t*) &tx, 1, 100);
	HAL_SPI_Transmit(&hspi1, (uint8_t*) &data, 1, 100);
	CSPASSIVE;
}
//*******************************************************************************************
//
// Function : icmp_send_request
// Description : Send ARP request packet to destination.
//
//*******************************************************************************************
void enc28j60SetBank(unsigned char address) {
	// set the bank (if needed)
	if ((address & BANK_MASK) != Enc28j60Bank) {
		// set the bank
		enc28j60WriteOp(ENC28J60_BIT_FIELD_CLR, ECON1,
				(ECON1_BSEL1 | ECON1_BSEL0));
		enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1,
				(address & BANK_MASK) >> 5);
		Enc28j60Bank = (address & BANK_MASK);
	}
}
//*******************************************************************************************
//
// Function : enc28j60Read
//
//*******************************************************************************************
unsigned char enc28j60Read(unsigned char address) {
	// select bank to read
	enc28j60SetBank(address);

	// do the read
	return enc28j60ReadOp(ENC28J60_READ_CTRL_REG, address);
}
//*******************************************************************************************
//
// Function : icmp_send_request
// Description : Send ARP request packet to destination.
//
//*******************************************************************************************
void enc28j60Write(unsigned char address, unsigned char data) {
	// select bank to write
	enc28j60SetBank(address);

	// do the write
	enc28j60WriteOp(ENC28J60_WRITE_CTRL_REG, address, data);
}
//*******************************************************************************************
//
// Function : enc28j60_read_phyreg
//
//*******************************************************************************************
unsigned short enc28j60_read_phyreg(unsigned char address) {
	unsigned short data;

	// set the PHY register address
	enc28j60Write(MIREGADR, address);
	enc28j60Write(MICMD, MICMD_MIIRD);

	// Loop to wait until the PHY register has been read through the MII
	// This requires 10.24us
	while ((enc28j60Read(MISTAT) & MISTAT_BUSY))
		;

	// Stop reading
	enc28j60Write(MICMD, MICMD_MIIRD);

	// Obtain results and return
	data = enc28j60Read( MIRDL);
	data |= enc28j60Read( MIRDH);

	return data;
}
//*******************************************************************************************
//
// Function : enc28j60PhyWrite
//
//*******************************************************************************************
void enc28j60PhyWrite(unsigned char address, unsigned short data) {
	// set the PHY register address
	enc28j60Write(MIREGADR, address);
	// write the PHY data
	enc28j60Write(MIWRL, Low(data));
	enc28j60Write(MIWRH, High(data));
	// wait until the PHY write completes
	while (enc28j60Read(MISTAT) & MISTAT_BUSY) {
		_delay_us(15);
	}
}
//*******************************************************************************************
//
// Function : icmp_send_request
// Description : Send ARP request packet to destination.
//
//*******************************************************************************************

void enc28j60_init() {
	// initialize I/O
	//DDRB |= _BV( DDB4 );
	//CSPASSIVE;

	// enable PB0, reset as output
	HAL_GPIO_WritePin(ETH_RST_GPIO_Port, ETH_RST_Pin, 0);
	HAL_Delay(50);
	// set output to Vcc, reset inactive
	HAL_GPIO_WritePin(ETH_RST_GPIO_Port, ETH_RST_Pin, 1);
	HAL_Delay(200);

	CSPASSIVE;

	// perform system reset
	enc28j60WriteOp(ENC28J60_SOFT_RESET, 0, ENC28J60_SOFT_RESET);

	_delay_ms(50);

	// check CLKRDY bit to see if reset is complete
	// The CLKRDY does not work. See Rev. B4 Silicon Errata point. Just wait.
	//while(!(enc28j60Read(ESTAT) & ESTAT_CLKRDY));
	// do bank 0 stuff
	// initialize receive buffer
	// 16-bit transfers, must write low byte first
	// set receive buffer start address
	next_packet_ptr = RXSTART_INIT;
	// Rx start
	enc28j60Write(ERXSTL, RXSTART_INIT & 0xFF);
	enc28j60Write(ERXSTH, RXSTART_INIT >> 8);
	// set receive pointer address
	enc28j60Write(ERXRDPTL, RXSTART_INIT & 0xFF);
	enc28j60Write(ERXRDPTH, RXSTART_INIT >> 8);
	// RX end
	enc28j60Write(ERXNDL, RXSTOP_INIT & 0xFF);
	enc28j60Write(ERXNDH, RXSTOP_INIT >> 8);
	// TX start
	enc28j60Write(ETXSTL, TXSTART_INIT & 0xFF);
	enc28j60Write(ETXSTH, TXSTART_INIT >> 8);
	// TX end
	enc28j60Write(ETXNDL, TXSTOP_INIT & 0xFF);
	enc28j60Write(ETXNDH, TXSTOP_INIT >> 8);

	// do bank 2 stuff
	// enable MAC receive
	enc28j60Write(MACON1, MACON1_MARXEN | MACON1_TXPAUS | MACON1_RXPAUS);

	// bring MAC out of reset
	//enc28j60Write(MACON2, 0x00);

	// enable automatic padding to 60bytes and CRC operations
	enc28j60Write(MACON3, MACON3_PADCFG0 | MACON3_TXCRCEN | MACON3_FRMLNEN);

	// Allow infinite deferals if the medium is continuously busy
	// (do not time out a transmission if the half duplex medium is
	// completely saturated with other people's data)
	enc28j60Write(MACON4, MACON4_DEFER);

	// Late collisions occur beyond 63+8 bytes (8 bytes for preamble/start of frame delimiter)
	// 55 is all that is needed for IEEE 802.3, but ENC28J60 B5 errata for improper link pulse
	// collisions will occur less often with a larger number.
	enc28j60Write(MACLCON2, 63);

	// Set non-back-to-back inter-packet gap to 9.6us.  The back-to-back
	// inter-packet gap (MABBIPG) is set by MACSetDuplex() which is called
	// later.
	enc28j60Write(MAIPGL, 0x12);
	enc28j60Write(MAIPGH, 0x0C);

	// Set the maximum packet size which the controller will accept
	// Do not send packets longer than MAX_FRAMELEN:
	enc28j60Write(MAMXFLL, MAX_FRAMELEN & 0xFF);
	enc28j60Write(MAMXFLH, MAX_FRAMELEN >> 8);

	// do bank 3 stuff
	// write MAC address
	// NOTE: MAC address in ENC28J60 is byte-backward
	// ENC28J60 is big-endian avr gcc is little-endian

	enc28j60Write(MAADR5, avr_mac[0]);
	enc28j60Write(MAADR4, avr_mac[1]);
	enc28j60Write(MAADR3, avr_mac[2]);
	enc28j60Write(MAADR2, avr_mac[3]);
	enc28j60Write(MAADR1, avr_mac[4]);
	enc28j60Write(MAADR0, avr_mac[5]);

	// no loopback of transmitted frames
	enc28j60PhyWrite(PHCON2, PHCON2_HDLDIS);

	// Magjack leds configuration, see enc28j60 datasheet, page 11
	// 0x476 is PHLCON LEDA=links status, LEDB=receive/transmit
	// enc28j60PhyWrite(PHLCON,0b0000 0100 0111 00 10);
	enc28j60PhyWrite(PHLCON, 0x0472);

	// do bank 1 stuff, packet filter:
	// For broadcast packets we allow only ARP packtets
	// All other packets should be unicast only for our mac (MAADR)
	//
	// The pattern to match on is therefore
	// Type     ETH.DST
	// ARP      BROADCAST
	// 06 08 -- ff ff ff ff ff ff -> ip checksum for theses bytes=f7f9
	// in binary these poitions are:11 0000 0011 1111
	// This is hex 303F->EPMM0=0x3f,EPMM1=0x30
	enc28j60Write(ERXFCON, ERXFCON_UCEN | ERXFCON_CRCEN | ERXFCON_PMEN);
	enc28j60Write(EPMM0, 0x3f);
	enc28j60Write(EPMM1, 0x30);
	enc28j60Write(EPMCSL, 0xf9);
	enc28j60Write(EPMCSH, 0xf7);

	// set inter-frame gap (back-to-back)
	enc28j60Write(MABBIPG, 0x12);

	// switch to bank 0
	enc28j60SetBank(ECON1);

	// enable interrutps
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, EIE, EIE_INTIE | EIE_PKTIE);

	// enable packet reception
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_RXEN);

	_delay_ms(20);
}
//*******************************************************************************************
//
// Function : enc28j60getrev
// Description : read the revision of the chip.
//
//*******************************************************************************************
unsigned char enc28j60getrev(void) {
	return (enc28j60Read(EREVID));
}
//*******************************************************************************************
//
// Function : enc28j60_packet_send
// Description : Send packet to network.
//
//*******************************************************************************************
void enc28j60_packet_send(unsigned char *buffer, unsigned short length) {
	//Set the write pointer to start of transmit buffer area
	enc28j60Write(EWRPTL, Low(TXSTART_INIT));
	enc28j60Write(EWRPTH, High(TXSTART_INIT));

	// Set the TXND pointer to correspond to the packet size given
	enc28j60Write(ETXNDL, Low(TXSTART_INIT + length));
	enc28j60Write(ETXNDH, High(TXSTART_INIT + length));

	// write per-packet control byte (0x00 means use macon3 settings)
	enc28j60WriteOp(ENC28J60_WRITE_BUF_MEM, 0, 0x00);

//	CSACTIVE;
	// issue write command
//	SPDR = ENC28J60_WRITE_BUF_MEM;
//	waitspi();
//	while(length)
//	{
//		length--;
//		// write data
//		SPDR = *buffer++;
//		waitspi();
//	}

	CSACTIVE;
	uint8_t tx = ENC28J60_WRITE_BUF_MEM;
	HAL_SPI_Transmit(&hspi1, (uint8_t*) &tx, 1, 100);
	HAL_SPI_Transmit(&hspi1, buffer, length, 100);
	CSPASSIVE;

	// send the contents of the transmit buffer onto the network
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS);

	// Reset the transmit logic problem. See Rev. B4 Silicon Errata point 12.
	if ((enc28j60Read(EIR) & EIR_TXERIF)) {
		enc28j60WriteOp(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_TXRTS);
	}
}
//*******************************************************************************************
//
// Function : enc28j60_mac_is_linked
// Description : return MAC link status.
//
//*******************************************************************************************
/*
 BYTE enc28j60_mac_is_linked(void)
 {
 if ( (enc28j60_read_phyreg(PHSTAT1) & PHSTAT1_LLSTAT ) )
 return 1;
 else
 return 0;
 }
 */
//*******************************************************************************************
//
// Function : enc28j60_packet_receive
// Description : check received packet and return length of data
//
//*******************************************************************************************
unsigned short enc28j60_packet_receive(unsigned char *rxtx_buffer,
		unsigned short max_length) {
	unsigned short rx_status, data_length;

	// check if a packet has been received and buffered
	// if( !(enc28j60Read(EIR) & EIR_PKTIF) ){
	// The above does not work. See Rev. B4 Silicon Errata point 6.
	if (enc28j60Read(EPKTCNT) == 0) {
		return 0;
	}

	// Set the read pointer to the start of the received packet
	enc28j60Write(ERDPTL, Low(next_packet_ptr));
	enc28j60Write(ERDPTH, High(next_packet_ptr));

	// read the next packet pointer
	LowPut(&next_packet_ptr, enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0));
	HighPut(&next_packet_ptr, enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0));

	// read the packet length (see datasheet page 43)
	LowPut(&data_length, enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0));
	HighPut(&data_length, enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0));
	data_length -= 4; //remove the CRC count

	// read the receive status (see datasheet page 43)
	LowPut(&rx_status, enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0));
	HighPut(&rx_status, enc28j60ReadOp(ENC28J60_READ_BUF_MEM, 0));

	if (data_length > (max_length - 1)) {
		data_length = max_length - 1;
	}

	// check CRC and symbol errors (see datasheet page 44, table 7-3):
	// The ERXFCON.CRCEN is set by default. Normally we should not
	// need to check this.
	if ((rx_status & 0x80) == 0) {
		// invalid
		data_length = 0;
	} else {
		// read data from rx buffer and save to rxtx_buffer
//		rx_status = data_length;
//		CSACTIVE;
		// issue read command
//		SPDR = ENC28J60_READ_BUF_MEM;
//		waitspi();
//		while(rx_status)
//		{
//			rx_status--;
//			SPDR = 0x00;
//			waitspi();
//			*rxtx_buffer++ = SPDR;
//		}
		CSACTIVE;
		uint8_t tx = ENC28J60_READ_BUF_MEM;
		HAL_SPI_Transmit(&hspi1, (uint8_t*) &tx, 1, 100);
		HAL_SPI_Receive(&hspi1, (uint8_t*) rxtx_buffer, data_length, 100);
		CSPASSIVE;
	}

	// Move the RX read pointer to the start of the next received packet
	// This frees the memory we just read out
	enc28j60Write(ERXRDPTL, Low(next_packet_ptr));
	enc28j60Write(ERXRDPTH, High(next_packet_ptr));

	// decrement the packet counter indicate we are done with this packet
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, ECON2, ECON2_PKTDEC);

	return data_length;
}

