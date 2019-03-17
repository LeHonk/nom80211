#[macro_use]
extern crate nom;

use nom::{be_u8, be_u16, be_u32};
use eui48::MacAddress;

pub struct Frame {
    fc: FrameControl,
    dur_id: u16,
    address1: MacAddress,
    address2: MacAddress,
    address3: MacAddress,
    address4: MacAddress,
    seq_ctrl: Option<SequenceControl>,
    qos_ctrl: Option<u16>,
    ht_ctrl: Option<u32>,
    body: Vec<u8>,
    fcs: u32,
}

pub struct FrameControl {
    version: u8,
    frametype: FrameType,
    to_ds: bool,
    from_ds: bool,
    more_fragments: bool,
    retry: bool,
    power_mgmt: bool,
    more_data: bool,
    protected_frame: bool,
    order: bool,
}

pub struct SequenceControl {
    sequence: u8,
    fragment: u16,
}

pub enum FrameType {
    Management(ManagementSubtype),
    Control(ControlSubtype),
    Data(DataSubtype),
    Extension(ExtensionSubtype),
}

pub enum ManagementSubtype {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    TimingAdvertisment,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAck,
    Reserved,
}

impl From<u8> for ManagementSubtype {
    fn from(subtype: u8) -> ManagementSubtype {
        match subtype {
            0x00 => ManagementSubtype::AssociationRequest,
            0x01 => ManagementSubtype::AssociationResponse,
            0x02 => ManagementSubtype::ReassociationRequest,
            0x03 => ManagementSubtype::ReassociationResponse,
            0x04 => ManagementSubtype::ProbeRequest,
            0x05 => ManagementSubtype::ProbeResponse,
            0x06 => ManagementSubtype::TimingAdvertisment,
            0x07 => ManagementSubtype::Reserved,
            0x08 => ManagementSubtype::Beacon,
            0x09 => ManagementSubtype::Atim,
            0x0A => ManagementSubtype::Disassociation,
            0x0B => ManagementSubtype::Authentication,
            0x0C => ManagementSubtype::Deauthentication,
            0x0D => ManagementSubtype::Action,
            0x0E => ManagementSubtype::ActionNoAck,
            0x0F => ManagementSubtype::Reserved,
            _ => ManagementSubtype::Reserved,
        }
    }
}

pub enum ControlSubtype {
    BeamformingReportPoll,
    VHTNDPAnouncement,
    ControlFrameExtension,
    ControlWrapper,
    BlockAckRequest,
    BlockAck,
    PSPoll,
    RTS,
    CTS,
    ACK,
    CFEnd,
    CFEndCFAck,
    Reserved,
}

impl From<u8> for ControlSubtype {
    fn from(subtype: u8) -> ControlSubtype {
        match subtype {
            0x04 => ControlSubtype::BeamformingReportPoll,
            0x05 => ControlSubtype::VHTNDPAnouncement,
            0x06 => ControlSubtype::ControlFrameExtension,
            0x07 => ControlSubtype::ControlWrapper,
            0x08 => ControlSubtype::BlockAckRequest,
            0x09 => ControlSubtype::BlockAck,
            0x0A => ControlSubtype::PSPoll,
            0x0B => ControlSubtype::RTS,
            0x0C => ControlSubtype::CTS,
            0x0D => ControlSubtype::ACK,
            0x0E => ControlSubtype::CFEnd,
            0x0F => ControlSubtype::CFEndCFAck,
            _ => ControlSubtype::Reserved,
        }
    }
}

pub struct DataSubtype {
    data: bool,
    ack: bool,
    poll: bool,
    qos: bool,
}

//pub enum DataSubtype {
//    Data,
//    DataCFAck,
//    DataCFPoll,
//    DataCFAckCFPoll,
//    Null,
//    NullCFAck,
//    NullCFPoll,
//    NullCFAckCFPoll,
//    QosData,
//    QosDataCFAck,
//    QosDataCFPoll,
//    QosDataCFAckCFPoll,
//    QosNull,
//    Reserved,
//    QosNullCFPoll,
//    QosNullCFAckCFPoll,
//}

//impl From<u8> for DataSubtype {
//    fn from(subtype: u8) -> DataSubtype {
//        match subtype {
//            0b0000 => DataSubtype::Data,
//            0b0001 => DataSubtype::DataCFAck,
//            0b0010 => DataSubtype::DataCFPoll,
//            0b0011 => DataSubtype::DataCFAckCFPoll,
//            0b0100 => DataSubtype::Null,
//            0b0101 => DataSubtype::NullCFAck,
//            0b0110 => DataSubtype::NullCFPoll,
//            0b0111 => DataSubtype::NullCFAckCFPoll,
//            0b1000 => DataSubtype::QosData,
//            0b1001 => DataSubtype::QosDataCFAck,
//            0b1010 => DataSubtype::QosDataCFPoll,
//            0b1011 => DataSubtype::QosDataCFAckCFPoll,
//            0b1100 => DataSubtype::QosNull,
//            0b1101 => DataSubtype::Reserved,
//            0b1110 => DataSubtype::QosNullCFPoll,
//            0b1111 => DataSubtype::QosNullCFAckCFPoll,
//            _ => DataSubtype::Reserved,
//        }
//    }
//}

pub enum ExtensionSubtype {
    DMGBeacon,
    Reserved,
}

impl From<u8> for ExtensionSubtype {
    fn from(subtype: u8) -> ExtensionSubtype {
        match subtype {
            0x00 => ExtensionSubtype::DMGBeacon,
            _ => ExtensionSubtype::Reserved,
        }
    }
}

named!(take_bool<(&[u8],usize), bool>,
    map!(take_bits!(u8, 1), |u| u==1)
);

named!(control_subtype<(&[u8],usize), ControlSubtype>, 
    map!(take_bits!(u8, 4), ControlSubtype::from)
);

named!(management_subtype<(&[u8],usize), ManagementSubtype>,
    map!(take_bits!(u8, 4), ManagementSubtype::from)
);

//named!(data_subtype<(&[u8],usize), DataSubtype>,
//    map!(take_bits!(u8, 4), DataSubtype::from)
//);

named!(data_subtype<(&[u8],usize), DataSubtype>,
    do_parse!(
        ack: call!(take_bool) >>
        poll: call!(take_bool) >>
        null: call!(take_bool) >>
        qos: call!(take_bool) >>
        ( DataSubtype{ data: !null, ack, poll, qos } )
    )
);

named!(extension_subtype<(&[u8],usize), ExtensionSubtype>,
    map!(take_bits!(u8, 4), ExtensionSubtype::from)
);

named!(control_type<(&[u8],usize), FrameType>,
    map!(control_subtype, |subtype| FrameType::Control(subtype))
);

named!(management_type<(&[u8],usize), FrameType>,
    map!(management_subtype, |subtype| FrameType::Management(subtype))
);

named!(data_type<(&[u8],usize), FrameType>,
    map!(data_subtype, |subtype| FrameType::Data(subtype))
);

named!(extension_type<(&[u8],usize), FrameType >,
    map!(extension_subtype, |subtype| FrameType::Extension(subtype))
);

named!(frametype<(&[u8],usize), FrameType>,
    switch!(take_bits!(u8, 2),
                0b00 => call!(control_type) |
                0b01 => call!(management_type) |
                0b10 => call!(data_type) |
                0b11 => call!(extension_type)
    )
);

named!(framecontrol<&[u8],FrameControl>,
    bits!(
        do_parse!(
            version: tag_bits!(u8, 2, 0b00) >>
            frametype: call!(frametype) >>
            to_ds: call!(take_bool) >>
            from_ds: call!(take_bool) >>
            more_fragments: call!(take_bool) >>
            retry: call!(take_bool) >>
            power_mgmt: call!(take_bool) >>
            more_data: call!(take_bool) >>
            protected_frame: call!(take_bool) >>
            order: call!(take_bool) >>
            ( FrameControl {
                version,
                frametype,
                to_ds,
                from_ds,
                more_fragments,
                retry,
                power_mgmt,
                more_data,
                protected_frame,
                order,
            } )
        )
    )
);

named!(sequencecontrol<&[u8],SequenceControl>,
   bits!(
       do_parse!(
           sequence: take_bits!(u8, 4) >>
           fragment: take_bits!(u16, 12) >> 
           ( SequenceControl { sequence, fragment } )
        )
    )
);

named!(frame<&[u8],Frame>,
    do_parse!(
        fc: call!(framecontrol) >>
        dur_id: be_u16 >>
        address1: map_res!(take!( 6 ), MacAddress::from_bytes) >>
        address2: map_res!(take!( 6 ), MacAddress::from_bytes) >>
        address3: map_res!(take!( 6 ), MacAddress::from_bytes) >>
        seq_ctrl: cond!(fc.more_fragments, call!(sequencecontrol)) >>
        address4: map_res!(take!( 6 ), MacAddress::from_bytes) >>
        qos_ctrl: cond!(false, be_u16) >>
        ht_ctrl: cond!(false, be_u32) >>
        body: many0!(be_u8) >>
        fcs: be_u32 >>
        ( Frame {
            fc,
            dur_id,
            address1,
            address2,
            address3,
            address4,
            seq_ctrl,
            qos_ctrl,
            ht_ctrl,
            body,
            fcs
        } )
    )
);
        //qos_control: cond!( match(fc.frametype) {
        //    FrameType::Data(d) => d.qos,
        //    _ => false
        //}, be_u16! ) >>

fn main() {
    println!("Hello, world!");
}
