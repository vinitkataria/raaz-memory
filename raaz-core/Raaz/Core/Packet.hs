{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Module that captures protocol packets.
module Raaz.Core.Packet
       ( -- * Packets and envelopes.
         -- $packets$
         Packet(..), Envelope(..), EnvelopeSize(..)
         -- * Some packets types
       , Raw
       , StickHeader(..)
       , StickFooter(..)
       ) where

import Control.Applicative
import Data.Monoid
import Foreign.Storable (Storable)

import Raaz.Core.Types
import Raaz.Core.Memory
import Raaz.Core.Util.Ptr
import Raaz.Core.Write
import Raaz.Core.Parse.Applicative

-- $packets$
-- Network protocols work with packets. Associated with a packet is
-- what we call an envelope which gives the meta-information of the
-- packet besides the actual payload of the packet. This type captures
-- a packet with envelope type @e@. There are two kinds of packets:
--
-- [Sealed packets:] A sealed packet is essentially a buffer, i.e. a
-- pointer to the start of the entire packet and the total packet
-- length. Typically sealed packets are the ones that are sent to the
-- pear or handed out to the layer below in network stack.
--
-- [Opened packet:] An opened packet contains the envelope, the start
-- of the actual payload and payload length. Open packets are the ones
-- that are handled by applications (or by layers above in the network
-- stack).
--
-- Envelope types are expected to be instances of the type class
-- `Envelope` and the member functions `unsafeOpen` and `unsafeSeal`
-- governs how the corresponding packet are opened and sealed.

-- | The packet associated with an envelope type @e@
data Packet e (s :: Status) where

  SealedPacket :: CryptoPtr -> BYTES Int -> Packet e Sealed

  OpenPacket   :: e -> CryptoPtr -> BYTES Int -> Packet e Open


-- | The status of the packet, whether it is sealed or open
data Status = Sealed
            | Open


-- | When enveloping a payload inside an envelope we require additional
-- space at the beginning and at the end of the payload.
--
-- > |-----------+---------+-----------|
-- > | head size | Payload | foot size |
-- > |-----------+---------+-----------|
-- >
data EnvelopeSize = EnvelopeSize { envelopeHeadSize :: BYTES Int
                                 , envelopeFootSize :: BYTES Int
                                 }

instance Monoid EnvelopeSize where
  mempty = EnvelopeSize 0 0
  mappend e1 e2 = EnvelopeSize { envelopeHeadSize = envelopeHeadSize e1 + envelopeHeadSize e2
                               , envelopeFootSize = envelopeFootSize e1 + envelopeFootSize e2
                               }

-- | An envelope class. Instances of this type determine how packets
-- of this type are sealed and open. Sealing and opening of
-- complicated packets might be stateful (e.g. encrypted packets) and
-- as such might require information stored in memory. The associated
-- types `SealMem` and `OpenMem` captures the memory types required
-- for sealing and opening.
class ( Memory (SealMem e)
      , Memory (OpenMem e)
      ) => Envelope e where

  -- | The memory used to seal an open packet with this envelope.
  type SealMem e :: *

  -- | The memory used to open a sealed packet with this envelope.
  type OpenMem e :: *


  -- | The envelope size required for @e@. Often the size is
  -- independent on the fixed for all values for the envelope @e@. For
  -- these cases there is a default definition which is essentially
  -- `maxEnvelopeSize`.
  envelopeSize :: e -> EnvelopeSize
  envelopeSize  = maxEnvelopeSize

  -- | The maximum size of the meta-information for envelopes of this
  -- size.  This function is essentially used to allocate
  -- space. Instances therefore /should not/ inspect the value of its
  -- argument.
  maxEnvelopeSize :: e -> EnvelopeSize

  -- | The combinator @`unsafeSeal` packet@ will seal an unsealed
  -- packet. Besides those portion of the memory before the start of
  -- the payload and some after its end, certain envelopes might even
  -- modify its payload (think of the enveloping doing some kind of
  -- encrypt-authenticate wrapping). Hence, this function is unsafe
  --
  --
  -- >            /----------- cptr
  -- >           v
  -- >  |--------+---------+--------|
  -- >  | Header | Payload | Footer |
  -- >  |---------------------------|
  -- >
  --

  unsafeSeal :: SealMem e -> Packet e Open -> IO (Packet e Sealed)

  -- | The combinator opens up a sealed packet. No length checks are
  -- possible on the buffer pointed by the payload pointer in the open
  -- packet and hence are not done. This function is therefore unsafe
  -- to use.
  unsafeOpen :: OpenMem e -> Packet e Sealed -> IO (Packet e Open)

-- | Envelope for raw packets.
data Raw = Raw

instance Envelope Raw where

  type SealMem Raw = ()
  type OpenMem Raw = ()

  maxEnvelopeSize  _ = mempty

  unsafeOpen _ (SealedPacket packetPtr packetSz)   = return $ OpenPacket Raw packetPtr packetSz
  {-# INLINE unsafeOpen #-}
  unsafeSeal _ (OpenPacket _ payloadPtr payloadSz) = return $ SealedPacket payloadPtr payloadSz
  {-# INLINE unsafeSeal #-}



-- | An envelope that sticks a header @h@ on the payload.
--
--
-- >  |--------+---------|
-- >  | Header | Payload |
-- >  |------------------|
newtype StickHeader h = StickHeader { unstickHeader :: h } deriving (Storable, EndianStore)

instance EndianStore h => Envelope (StickHeader h) where

  type SealMem (StickHeader h) = ()
  type OpenMem (StickHeader h) = ()

  maxEnvelopeSize sH = EnvelopeSize (byteSize sH) 0

  unsafeOpen _ (SealedPacket packetPtr packetSz) = OpenPacket <$> unsafeRunParser headerP packetPtr
                                                              <*> pure payloadPtr
                                                              <*> pure payloadSz
    where headerP     = parse
          headerSz    = parseWidth headerP
          -- Payload
          payloadSz   = packetSz - headerSz
          payloadPtr  = packetPtr `movePtr` headerSz  -- Strip the header off.



  unsafeSeal _ (OpenPacket sH payloadPtr payloadSz) = unsafeWrite (write sH) packetPtr
                                                    >> return (SealedPacket packetPtr packetSz)
    where packetPtr   = payloadPtr `movePtr` negate headerSz -- accommodate the header
          packetSz    = payloadSz + headerSz
          headerSz    = byteSize sH


-- | An envelope that sticks a footer on the payload.
--
-- >  |---------+--------|
-- >  | Payload | Footer |
-- >  |------------------|
newtype StickFooter f = StickFooter { unstickFooter :: f } deriving (Storable, EndianStore)

instance EndianStore f => Envelope (StickFooter f) where

  type SealMem (StickFooter f) = ()
  type OpenMem (StickFooter f) = ()

  maxEnvelopeSize sF = EnvelopeSize 0 $ byteSize sF


  unsafeOpen _ (SealedPacket packetPtr packetSz) = OpenPacket <$> unsafeRunParser (skipPayload *> footP) packetPtr
                                                              <*> pure packetPtr
                                                              <*> pure payloadSz
    where footP     = parse
          footSz    = parseWidth footP
          -- Payload
          skipPayload = skip payloadSz
          payloadSz   = packetSz - footSz   -- shrink the packet to payload

  unsafeSeal _ (OpenPacket sF payloadPtr payloadSz) =
    unsafeWrite writeFooter payloadPtr >> return (SealedPacket payloadPtr packetSz)
    where writeFooter = move payloadSz <> write sF
          packetSz    = payloadSz + byteSize sF
