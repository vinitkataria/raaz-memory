{-|

Portable C implementation of SHA512 hash.

-}

{-# LANGUAGE ForeignFunctionInterface  #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# OPTIONS_GHC -fno-warn-orphans      #-}
{-# CFILES raaz/hash/sha512/portable.c #-}

module Raaz.Hash.Sha512.CPortable (sha512Compress) where

import Foreign.Ptr

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Types

import Raaz.Hash.Sha512.Type

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: Ptr SHA512 -> Int -> CryptoPtr -> IO ()

sha512Compress :: CryptoCell SHA512 -> BLOCKS SHA512 -> CryptoPtr -> IO ()
sha512Compress cc nblocks buffer = withCell cc action
  where action ptr = c_sha512_compress (castPtr ptr) n buffer
        n = fromEnum nblocks
{-# INLINE sha512Compress #-}

instance Gadget (CGadget SHA512) where
  type PrimitiveOf (CGadget SHA512) = SHA512
  type MemoryOf (CGadget SHA512)    = CryptoCell SHA512
  newGadgetWithMemory               = return . CGadget
  getMemory (CGadget m)             = m
  apply (CGadget cc)                = sha512Compress cc

instance PaddableGadget (CGadget SHA512)
