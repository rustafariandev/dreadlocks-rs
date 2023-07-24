use num_enum::TryFromPrimitive;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum SshAgentRequestType {
    RsaIdentities = 1,
    RsaChallenge = 3,
    AddRsaIdentity = 7,
    RemoveRsaIdentity = 8,
    RemoveAllRsaIdentities = 9,

    RequestIdentities = 11,
    SignRequest = 13,
    AddIdentity = 17,
    RemoveIdentity = 18,
    RemoveAllIdentities = 19,

    /* smartcard */
    AddSmartcardKey = 20,
    RemoveSmartcardKey = 21,

    /* LOCK/UNLOCK THE AGENT */
    Lock = 22,
    Unlock = 23,

    AddRsaIdConstrained = 24,
    AddIdConstrained = 25,
    AddSmartcardKeyConstrained = 26,

    /* GENERIC EXTENSION MECHANISM */
    Extension = 27,
}

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum SshAgentResponseType {
    /* Legacy */
    RsaIdentitiesAnswer = 2,
    RsaResponse = 4,

    /* Messages for the authentication agent connection. */
    Failure = 5,
    Success = 6,

    /* private OpenSSH extensions for SSH2 */
    IdentitiesAnswer = 12,
    SignResponse = 14,

    /* GENERIC EXTENSION MECHANISM */
    ExtensionFailure = 28,
}
