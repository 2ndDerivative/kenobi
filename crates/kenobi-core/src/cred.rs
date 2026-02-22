pub mod usage {
    pub trait InboundUsable {}
    pub trait OutboundUsable {}

    #[derive(Debug)]
    pub enum Inbound {}
    impl InboundUsable for Inbound {}
    #[derive(Debug)]
    pub enum Outbound {}
    impl OutboundUsable for Outbound {}

    #[derive(Debug)]
    pub enum Both {}
    impl InboundUsable for Both {}
    impl OutboundUsable for Both {}
}
