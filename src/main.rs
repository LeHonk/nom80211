use eui48::MacAddress;
use nom::bits::bits;
use nom::bits::complete::{tag,take};
use nom::combinator::{cond, map, map_res};
use nom::Err;
use nom::error::ErrorKind;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;

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
    Trigger,
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
            0x02 => ControlSubType::Trigger,
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

fn take_bool(i: (&[u8], usize)) -> IResult<(&[u8], usize), bool> {
    map(take(1usize), |u: u8| u == 1)(i)
}

fn control_subtype(i: (&[u8], usize)) -> IResult<(&[u8], usize), ControlSubtype> {
    map(take(4usize), |c: u8| ControlSubtype::from(c))(i)
}

fn management_subtype(i: (&[u8], usize)) -> IResult<(&[u8], usize), ManagementSubtype> {
    map(take(4usize), |m: u8| ManagementSubtype::from(m))(i)
}

//named!(data_subtype<(&[u8],usize), DataSubtype>,
//    map!(take_bits!(u8, 4), DataSubtype::from)
//);

fn data_subtype(i: (&[u8], usize)) -> IResult<(&[u8], usize), DataSubtype> {
    let (i, ack) = take_bool(i)?;
    let (i, poll) = take_bool(i)?;
    let (i, _null) = take_bool(i)?;
    let (i, qos) = take_bool(i)?;
    Ok((
        i,
        DataSubtype {
            data: false,
            ack,
            poll,
            qos,
        },
    ))
}

fn extension_subtype(i: (&[u8], usize)) -> IResult<(&[u8], usize), ExtensionSubtype> {
    map(take(4usize), |e: u8| ExtensionSubtype::from(e))(i)
}

fn control_type(i: (&[u8], usize)) -> IResult<(&[u8], usize), FrameType> {
    map(control_subtype, |subtype| FrameType::Control(subtype))(i)
}

fn management_type(i: (&[u8], usize)) -> IResult<(&[u8], usize), FrameType> {
    map(management_subtype, |subtype| FrameType::Management(subtype))(i)
}

fn data_type(i: (&[u8], usize)) -> IResult<(&[u8], usize), FrameType> {
    map(data_subtype, |subtype| FrameType::Data(subtype))(i)
}

fn extension_type(i: (&[u8], usize)) -> IResult<(&[u8], usize), FrameType> {
    map(extension_subtype, |subtype| FrameType::Extension(subtype))(i)
}

fn frametype(i: (&[u8], usize)) -> IResult<(&[u8], usize), FrameType> {
    let (i, frametype) = take(2usize)(i)?;
    match frametype {
        0b00 => control_type(i),
        0b01 => management_type(i),
        0b10 => data_type(i),
        0b11 => extension_type(i),
        _ => Err(Err::Error((i, ErrorKind::Tag))),
    }
}

fn framecontrol(i: (&[u8], usize)) -> IResult<(&[u8], usize), FrameControl> {
    let (i, version) = tag(0b00, 2usize)(i)?;
    let (i, frametype) = frametype(i)?;
    let (i, to_ds) = take_bool(i)?;
    let (i, from_ds) = take_bool(i)?;
    let (i, more_fragments) = take_bool(i)?;
    let (i, retry) = take_bool(i)?;
    let (i, power_mgmt) = take_bool(i)?;
    let (i, more_data) = take_bool(i)?;
    let (i, protected_frame) = take_bool(i)?;
    let (i, order) = take_bool(i)?;
    Ok((
        i,
        FrameControl {
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
        },
    ))
}

fn sequencecontrol(i: (&[u8],usize)) -> IResult<(&[u8],usize), SequenceControl> {
    let (i, sequence) = take(4usize)(i)?;  
    let (i, fragment) = take(12usize)(i)?;
    Ok((i, SequenceControl { sequence, fragment }))
}

fn mac_address(i: &[u8]) -> IResult<&[u8], MacAddress> {
    use nom::bytes::complete::take;
    map_res(take(6usize), MacAddress::from_bytes)(i)
}

fn qos(fc: &FrameControl) -> bool {
    match &fc.frametype {
        FrameType::Data(d) => d.qos,
        _ => false,
    }
}

fn frame(i: &[u8]) -> IResult<&[u8], Frame> {
    let (i, fc) = bits(framecontrol)(i)?;
    let (i, dur_id) = be_u16(i)?;
    let (i, address1) = mac_address(i)?;
    let (i, address2) = mac_address(i)?;
    let (i, address3) = mac_address(i)?;
    let (i, seq_ctrl) = cond(fc.more_fragments, bits(sequencecontrol))(i)?;
    let (i, address4) = mac_address(i)?;
    let (i, qos_ctrl) = cond(qos(&fc), be_u16,)(i)?;
    let (i, ht_ctrl) = cond(false, be_u32)(i)?; // TODO Is this correct?
    let (i, body) = count(be_u8, 0usize)(i)?; // TODO How many bytes in data?
    let (i, fcs) = be_u32(i)?;
    Ok((
        i,
        Frame {
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
            fcs,
        },
    ))
}

fn main() {
    println!("Hello, world!");
}
