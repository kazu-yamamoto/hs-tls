module Network.TLS.Crypto.Types where

import Crypto.PubKey.ECC.Types (CurveName(..))
import Data.Word (Word16)

data Group = P256 | P384 | P521 | X25519 | X448
           | FFDHE2048 | FFDHE3072 | FFDHE4096 | FFDHE6144 | FFDHE8192
           | UnknownGroup Word16
           deriving (Eq, Show)

-- EnumSafe16 cannot be used due to recycling imports.
fromGroup :: Group -> Word16
fromGroup P256      =  23
fromGroup P384      =  24
fromGroup P521      =  25
fromGroup X25519    =  29
fromGroup X448      =  30
fromGroup FFDHE2048 = 256
fromGroup FFDHE3072 = 257
fromGroup FFDHE4096 = 258
fromGroup FFDHE6144 = 259
fromGroup FFDHE8192 = 260
fromGroup (UnknownGroup w16) = w16

toGroup :: Word16 -> Group
toGroup  23 = P256
toGroup  24 = P384
toGroup  25 = P521
toGroup  29 = X25519
toGroup  30 = X448
toGroup 256 = FFDHE2048
toGroup 257 = FFDHE3072
toGroup 258 = FFDHE4096
toGroup 259 = FFDHE6144
toGroup 260 = FFDHE8192
toGroup w16 = UnknownGroup w16

data NamedCurve =
      SEC CurveName
    | BrainPool BrainPoolCurve
    | NamedCurve_arbitrary_explicit_prime_curves
    | NamedCurve_arbitrary_explicit_char2_curves
    deriving (Show,Eq)

data BrainPoolCurve =
      BrainPoolP512R1 -- 28
    | BrainPoolP384R1 -- 27
    | BrainPoolP256R1 -- 26
    deriving (Show,Eq)

availableEllipticCurves :: [NamedCurve]
availableEllipticCurves = [SEC SEC_p256r1, SEC SEC_p384r1, SEC SEC_p521r1]

fromNamedCurve :: NamedCurve -> Word16
fromNamedCurve NamedCurve_arbitrary_explicit_prime_curves = 0xFF01
fromNamedCurve NamedCurve_arbitrary_explicit_char2_curves = 0xFF02
fromNamedCurve (SEC nc) = maybe (error "named curve: internal error") id $ fromCurveName nc
fromNamedCurve (BrainPool BrainPoolP512R1) = 28
fromNamedCurve (BrainPool BrainPoolP384R1) = 27
fromNamedCurve (BrainPool BrainPoolP256R1) = 26

toNamedCurve :: Word16 -> Maybe NamedCurve
toNamedCurve 0xFF01 = Just NamedCurve_arbitrary_explicit_prime_curves
toNamedCurve 0xFF02 = Just NamedCurve_arbitrary_explicit_char2_curves
toNamedCurve 26     = Just (BrainPool BrainPoolP256R1)
toNamedCurve 27     = Just (BrainPool BrainPoolP384R1)
toNamedCurve 28     = Just (BrainPool BrainPoolP512R1)
toNamedCurve n      = SEC <$> toCurveName n

fromNamedCurveToGroup :: NamedCurve -> Group
fromNamedCurveToGroup (SEC SEC_p256r1) = P256
fromNamedCurveToGroup (SEC SEC_p384r1) = P384
fromNamedCurveToGroup (SEC SEC_p521r1) = P521
fromNamedCurveToGroup _                = error "fromNamedCurveToGroup"

toCurveName :: Word16 -> Maybe CurveName
toCurveName  1 = Just SEC_t163k1
toCurveName  2 = Just SEC_t163r1
toCurveName  3 = Just SEC_t163r2
toCurveName  4 = Just SEC_t193r1
toCurveName  5 = Just SEC_t193r2
toCurveName  6 = Just SEC_t233k1
toCurveName  7 = Just SEC_t233r1
toCurveName  8 = Just SEC_t239k1
toCurveName  9 = Just SEC_t283k1
toCurveName 10 = Just SEC_t283r1
toCurveName 11 = Just SEC_t409k1
toCurveName 12 = Just SEC_t409r1
toCurveName 13 = Just SEC_t571k1
toCurveName 14 = Just SEC_t571r1
toCurveName 15 = Just SEC_p160k1
toCurveName 16 = Just SEC_p160r1
toCurveName 17 = Just SEC_p160r2
toCurveName 18 = Just SEC_p192k1
toCurveName 19 = Just SEC_p192r1
toCurveName 20 = Just SEC_p224k1
toCurveName 21 = Just SEC_p224r1
toCurveName 22 = Just SEC_p256k1
toCurveName 23 = Just SEC_p256r1
toCurveName 24 = Just SEC_p384r1
toCurveName 25 = Just SEC_p521r1
--toCurveName 26 = Just  Brainpool_P256r1
--toCurveName 27 = Just Brainpool_P384r1
--toCurveName 28 = Just Brainpool_P512r1
toCurveName _  = Nothing

fromCurveName :: CurveName -> Maybe Word16
fromCurveName SEC_t163k1 = Just  1
fromCurveName SEC_t163r1 = Just  2
fromCurveName SEC_t163r2 = Just  3
fromCurveName SEC_t193r1 = Just  4
fromCurveName SEC_t193r2 = Just  5
fromCurveName SEC_t233k1 = Just  6
fromCurveName SEC_t233r1 = Just  7
fromCurveName SEC_t239k1 = Just  8
fromCurveName SEC_t283k1 = Just  9
fromCurveName SEC_t283r1 = Just 10
fromCurveName SEC_t409k1 = Just 11
fromCurveName SEC_t409r1 = Just 12
fromCurveName SEC_t571k1 = Just 13
fromCurveName SEC_t571r1 = Just 14
fromCurveName SEC_p160k1 = Just 15
fromCurveName SEC_p160r1 = Just 16
fromCurveName SEC_p160r2 = Just 17
fromCurveName SEC_p192k1 = Just 18
fromCurveName SEC_p192r1 = Just 19
fromCurveName SEC_p224k1 = Just 20
fromCurveName SEC_p224r1 = Just 21
fromCurveName SEC_p256k1 = Just 22
fromCurveName SEC_p256r1 = Just 23
fromCurveName SEC_p384r1 = Just 24
fromCurveName SEC_p521r1 = Just 25
fromCurveName _          = Nothing
