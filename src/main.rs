use argh::FromArgs;

#[cfg(not(any(feature="donna",feature="dalek")))]
compile_error!("Please enable either `donna` or `dalek` crate feature");

#[cfg(all(feature="donna",feature="dalek"))]
compile_error!("Please enable only one of `donna` or `dalek` crate features");

#[cfg(feature="donna")]
use elliptic::curve25519::{donna,keygen,sign,verify};

#[cfg(feature="dalek")]
use x25519_dalek::{StaticSecret,PublicKey};
#[cfg(feature="dalek")]
use ed25519_dalek::{PublicKey as EdPublicKey,Signature, ExpandedSecretKey as EdSecretKey};

/// Use curve25519 and ed25519 from command line
#[derive(FromArgs)]
struct Opts {
   #[argh(subcommand)]
   cmd: Cmd,
}

/// Use curve25519 and ed25519 from command line
#[derive(FromArgs)]
#[argh(subcommand)]
enum Cmd {
  GenPriv(GenPriv),
  Massage(Massage),
  Keygen(Keygen),
  BasePoint(BasePoint),
  Donna(Donna),
  Sign(Sign),
  Verify(Verify),
  Curve2Ed(Curve2Ed),
  Ed2Curve(Ed2Curve),
  ExpandEd(ExpandEd),
  ScalarCommand(ScalarCommand),
}

/// Generate new private curve25519 or ed25519 key and print it as hex to stdout
#[derive(FromArgs)]
#[argh(subcommand, name = "gen")]
struct GenPriv {
}

/// Set and clear bits from a 32-byte hex string specified on stdin for
/// it to be suitable x25519 private key
#[derive(FromArgs)]
#[argh(subcommand, name = "massage")]
struct Massage {
}

/// Read private key from stdin and print public key to stdout.
#[derive(FromArgs)]
#[argh(subcommand, name = "pub")]
struct Keygen {
}

/// Print basepoint (9) as hex.
#[derive(FromArgs)]
#[argh(subcommand, name = "base")]
struct BasePoint {
}

/// Read private key from stdin and public key from command
/// line argument, then print shared key as hex to stdout
#[derive(FromArgs)]
#[argh(subcommand, name = "mul")]
struct Donna {
    #[argh(positional,from_str_fn(readhex32))]
    pubkey: [u8; 32],
}

/// Sign stdin data using private key read from specified file
#[derive(FromArgs)]
#[argh(subcommand, name = "sign")]
struct Sign {
    #[argh(positional)]
    privkey_file: std::path::PathBuf,

    /// override random seed used for making a signature
    #[argh(option,from_str_fn(readhex64))]
    random: Option<[u8; 64]>,

    /// use ed25519 seed value instead of curve25519 point for signing
    #[argh(switch)]
    ed: bool,

    /// don't set high bit in signature even with --negative to make signature compatible
    #[argh(switch)]
    no_sign_bit: bool,

    /// use sign bit in signature even in --ed mode, to allow verification with a curve25519 key
    #[argh(switch)]
    use_sign_bit: bool,

    /// assume ed25519 key should be negative when given a curve25515 point as a privkey
    #[argh(switch)]
    negative: bool,
}

/// Verify signature of data supplied to stdin
#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
struct Verify {
    #[argh(positional,from_str_fn(readhex32))]
    pubkey: [u8; 32],

    #[argh(positional,from_str_fn(readhex64))]
    signature: [u8; 64],

    /// expect pubkey in ed25519 format instead of curve25519 and fail if signautre contains a sign.
    #[argh(switch)]
    ed: bool,

    /// treat supplied curve25519 key as negative even if high bit in signature is not set
    #[argh(switch)]
    negative: bool,
}

/// Convert MontgomeryPoint to CompressedEdwardsY point
#[derive(FromArgs)]
#[argh(subcommand, name = "curve2ed")]
struct Curve2Ed {
    #[argh(positional,from_str_fn(readhex32))]
    point: [u8; 32],

    /// use 1 for sign instead of 0
    #[argh(option)]
    negative: bool,
}

/// Extract private or public key from ed25519 seed value (read from stdin)
#[derive(FromArgs)]
#[argh(subcommand, name = "expand_ed")]
struct ExpandEd {
    /// print 64 bytes instead of 32
    #[argh(switch)]
    also_nonce: bool,

    /// print public ed25519 key instead of secret one
    #[argh(switch)]
    pubkey: bool,
}

/// Convert CompressedEdwardsY to MontgomeryPoint and a sign (0 or 1), space-separated
#[derive(FromArgs)]
#[argh(subcommand, name = "ed2curve")]
struct Ed2Curve {
    #[argh(positional,from_str_fn(readhex32))]
    point: [u8; 32],
}


/// Subcommands involving scalars or add/sub
#[derive(FromArgs)]
#[argh(subcommand, name = "scalar")]
struct ScalarCommand {
   #[argh(subcommand)]
   cmd: ScalarCmd,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum ScalarCmd {
  ScalarCanonicalize(ScalarCanonicalize),
  ScalarInvert(ScalarInvert),
  ScalarMul(ScalarMul),
  ScalarAdd(ScalarAdd),
  ScalarSub(ScalarSub),
  ScalarMontMul(ScalarMontMul),
  ScalarEdMul(ScalarEdMul),
  EdAdd(EdAdd),
  EdSub(EdSub),
}

/// Read 32 or 64 bytes and output 32 bytes of a canonical `curve25519_dalek::scalar::Scalar`
#[derive(FromArgs)]
#[argh(subcommand, name = "canonicalize")]
struct ScalarCanonicalize {
    #[argh(positional)]
    scalaresque: String,
}

/// Invert given nonzero canonical scalar value with a modulo
#[derive(FromArgs)]
#[argh(subcommand, name = "invert")]
struct ScalarInvert {
    #[argh(positional,from_str_fn(readhex32))]
    scalar: [u8; 32],
}

/// Multiply two given scalars with a modulo
#[derive(FromArgs)]
#[argh(subcommand, name = "mul")]
struct ScalarMul {
    #[argh(positional,from_str_fn(readhex32))]
    scalar1: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    scalar2: [u8; 32],
}

/// Add two given canonical scalaras, with a modulo
#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
struct ScalarAdd {
    #[argh(positional,from_str_fn(readhex32))]
    scalar1: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    scalar2: [u8; 32],
}

/// Subtract two given canonical scalaras, modulo
#[derive(FromArgs)]
#[argh(subcommand, name = "sub")]
struct ScalarSub {
    #[argh(positional,from_str_fn(readhex32))]
    scalar1: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    scalar2: [u8; 32],
}


/// Multiply given scalar by a curve25519 (Montgomery) point, outputting a point
#[derive(FromArgs)]
#[argh(subcommand, name = "mul_mont")]
struct ScalarMontMul {
    #[argh(positional,from_str_fn(readhex32))]
    scalar: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    point: [u8; 32],
}

/// Multiply given scalar by a ed25519 (Edwards) point, outputting a point
#[derive(FromArgs)]
#[argh(subcommand, name = "mul_ed")]
struct ScalarEdMul {
    #[argh(positional,from_str_fn(readhex32))]
    scalar: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    point: [u8; 32],
}

/// Add two ed25519 points
#[derive(FromArgs)]
#[argh(subcommand, name = "add_ed")]
struct EdAdd {
    #[argh(positional,from_str_fn(readhex32))]
    point1: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    point2: [u8; 32],
}

/// Subtract two ed25519 points
#[derive(FromArgs)]
#[argh(subcommand, name = "sub_ed")]
struct EdSub {
    #[argh(positional,from_str_fn(readhex32))]
    point1: [u8; 32],
    #[argh(positional,from_str_fn(readhex32))]
    point2: [u8; 32],
}



fn readhex32(x:&str) -> std::result::Result<[u8;32], String> {
    use std::convert::TryInto;
    match hex::decode(x) {
        Err(e) => Err(format!("{}", e)),
        Ok(x) if x.len() == 32 => {
            let xx : &[u8;32] = x[..].try_into().unwrap();
            Ok(*xx)
        }
        Ok(_) => Err("Argument must be 32 hex-encoded bytes".to_string())
    }
}
fn readhex64(x:&str) -> std::result::Result<[u8;64], String> {
    match hex::decode(x) {
        Err(e) => Err(format!("{}", e)),
        Ok(x) if x.len() == 64 => {
            let xx : &[u8;64] = arrayref::array_ref!(x,0,64);
            Ok(*xx)
        }
        Ok(_) => Err("Argument must be 64 hex-encoded bytes".to_string())
    }
}

fn read32from(mut f: impl std::io::Read) -> Result<[u8;32]> {
    let mut pk = [0u8; 64];
    f.read_exact(&mut pk[..])?;
    let mut pkbuf = [0u8; 32];
    hex::decode_to_slice(&pk[..], &mut pkbuf[..])?;
    Ok(pkbuf)
}

fn read32fromstdin() -> Result<[u8;32]> {
    read32from(std::io::stdin())
}
fn read32fromfile(f: impl AsRef<std::path::Path>) -> Result<[u8;32]> {
    let f = std::fs::File::open(f)?;
    read32from(f)
}


type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, Error>;


fn main() -> Result<()> {
    use std::io::Read;
    let opts: Opts = argh::from_env();
    match opts.cmd {
        Cmd::GenPriv(_) => {
            let mut buf = [0u8;32];
            getrandom::getrandom(&mut buf[..])?;
            buf[0] &= 0xF8;
            buf[31] &= 0x7F;
            buf[31] |= 0x40;
            println!("{}", hex::encode(&buf[..]));
        }
        Cmd::Massage(_) => {
            let mut buf = read32fromstdin()?;
            buf[0] &= 0xF8;
            buf[31] &= 0x7F;
            buf[31] |= 0x40;
            println!("{}", hex::encode(&buf[..]));
        }
        Cmd::BasePoint(_) => {
            let mut buf = [0u8;32];
            buf[0] = 9;
            println!("{}", hex::encode(&buf[..]));
        }
        Cmd::Keygen(_) => {
            let pkbuf = read32fromstdin()?;
            let buf : [u8;32];
            #[cfg(feature="donna")] {
                buf = keygen(&pkbuf);
            }
            #[cfg(feature="dalek")] {
                let pk = StaticSecret::from(pkbuf);
                let pubk = PublicKey::from(&pk);
                buf = *pubk.as_bytes();
            }
            println!("{}", hex::encode(&buf[..]));
        }
        Cmd::Donna(d) => {
            let pkbuf = read32fromstdin()?;
            let buf : [u8;32];
            #[cfg(feature="donna")] {
                buf = donna(&pkbuf, &d.pubkey).ok_or("donna failed")?;
            }
            #[cfg(feature="dalek")] {
                let pk = StaticSecret::from(pkbuf);
                let pubk = PublicKey::from(d.pubkey);
                let sh = pk.diffie_hellman(&pubk);
                buf = *sh.as_bytes();
            }
            println!("{}", hex::encode(&buf[..]));
        }
        Cmd::Sign(s) => {
            let mut rnd = [0u8; 64];
            match s.random {
                Some(x) => rnd.copy_from_slice(&x[..]),
                None => getrandom::getrandom(&mut rnd[..])?,
            }
            let pkbuf = read32fromfile(s.privkey_file)?;
            let mut buf = Vec::with_capacity(4096);
            std::io::stdin().read_to_end(&mut buf)?;
            #[cfg(feature="donna")] {
                if s.ed || s.negative || s.no_sign_bit || s.use_sign_bit {
                    Err("Curve25519tool is built without this feature")?
                }
                let signat = sign(&pkbuf,&buf[..],&rnd).ok_or("sign failed")?;
                println!("{}", hex::encode(&signat[..]));
            }
            #[cfg(feature="dalek")] {
                let privk;
                let pubkey;

                let negative : bool; 

                if s.ed {
                    if s.no_sign_bit {
                        Err("--no-sign-bit is not meaningful with --ed")?
                    }
                    if s.negative {
                        Err("--negative is not meaningful with --ed")?
                    }
                    if s.random.is_some() {
                        Err("--random is not meaningful with --ed")?
                    }
                    let k = ed25519_dalek::SecretKey::from_bytes(&pkbuf[..]).unwrap();
                    privk = k.expand::<sha2::Sha512>();
                    pubkey = EdPublicKey::from_expanded_secret(&privk);
                    negative = pubkey.as_bytes()[31] & 0x80 != 0;
                } else {
                    if s.use_sign_bit {
                        Err("--use-sign-bit is already on without --ed")?
                    }
                    negative = s.negative;
                    let mut pkbuf2 = [0u8; 64];
                    pkbuf2[0..32].copy_from_slice(&pkbuf[..]);
                    pkbuf2[32..64].copy_from_slice(&rnd[0..32]);
                    privk = EdSecretKey::from_bytes(&pkbuf2[..]).unwrap();
                    
                    let pubk = PublicKey::from(&StaticSecret::from(pkbuf));
                    let pubk = curve25519_dalek::montgomery::MontgomeryPoint(*pubk.as_bytes());
                    let pubk = pubk.to_edwards(if negative { 1 } else { 0 }).unwrap().compress();
                    pubkey = EdPublicKey::from_bytes(pubk.as_bytes()).unwrap();
                }

                let signat = privk.sign::<sha2::Sha512>(&buf[..], &pubkey);
                let mut signat = signat.to_bytes();

                if negative {
                    if (s.ed && s.use_sign_bit) || (!s.ed && !s.no_sign_bit) {
                        signat[63] |= 0x80;
                    }
                }

                println!("{}", hex::encode(&signat[..]));
            }
        }
        Cmd::Verify(v) => {
            let mut buf = Vec::with_capacity(4096);
            std::io::stdin().read_to_end(&mut buf)?;

            #[cfg(feature="donna")] {
                if s.ed || s.negative {
                    Err("Curve25519tool is built without this feature")?
                }
                if ! verify(&v.signature, &v.pubkey, &buf[..]) {
                    Err("Signature verification failed")?;
                }
            }
            #[cfg(feature="dalek")] {
                let mut sbuf = v.signature;
                let mut sign = if sbuf[63] & 0x80 != 0 {
                    if v.ed {
                        Err("Signature contains a sign bit, which is not meaningul in --ed mode")?
                    }
                    sbuf[63] &= 0x7F;
                    1
                } else {
                    0
                };
                let s = Signature::from_bytes(&sbuf[..]).map_err(|e|format!("{}",e))?;
                let pubkey;

                if v.negative {
                    sign = 1;
                }
                
                if v.ed {
                    if v.negative {
                        Err("--negative is not meaningful with --ed")?
                    }
                    pubkey = EdPublicKey::from_bytes(&v.pubkey[..]).unwrap();
                } else {
                    let pk = curve25519_dalek::montgomery::MontgomeryPoint(v.pubkey);
                    let pk = pk.to_edwards(sign).unwrap().compress();
                    pubkey = EdPublicKey::from_bytes(pk.as_bytes()).unwrap();
                }

                if let Err(_) = pubkey.verify::<sha2::Sha512>(&buf[..], &s) {
                    Err("Signature verification failed")?;
                }
            }
        }
        Cmd::Curve2Ed(x) => {
            #[cfg(feature="donna")] {
                Err("Curve25519tool is built without this feature")?
            }
            #[cfg(feature="dalek")] {
                let pk = curve25519_dalek::montgomery::MontgomeryPoint(x.point);
                let pk = pk.to_edwards(if x.negative { 1 } else { 0 }).unwrap().compress();
                println!("{}", hex::encode(pk.as_bytes()));
            }
        }
        Cmd::Ed2Curve(x) => {
            #[cfg(feature="donna")] {
                Err("Curve25519tool is built without this feature")?
            }
            #[cfg(feature="dalek")] {
                let sign = x.point[31] & 0x80 != 0;
                let pk = curve25519_dalek::edwards::CompressedEdwardsY(x.point);
                let pk = pk.decompress().ok_or("Something wrong with your point")?.to_montgomery();
                println!("{} sign {}", hex::encode(pk.as_bytes()), if sign { 1 } else { 0 });
            }
        }
        Cmd::ExpandEd(x) => {
            #[cfg(feature="donna")] {
                Err("Curve25519tool is built without this feature")?
            }
            #[cfg(feature="dalek")] {
                let pkbuf = read32fromstdin()?;
                let pk = ed25519_dalek::SecretKey::from_bytes(&pkbuf[..]).unwrap();
                let pk = pk.expand::<sha2::Sha512>();
                if x.pubkey {
                    let pubk = EdPublicKey::from_expanded_secret(&pk);
                    println!("{}", hex::encode(&pubk.to_bytes()[..]));
                } else {
                    let pk = pk.to_bytes();
                    if x.also_nonce {
                        println!("{}", hex::encode(&pk[..]));
                    } else {
                        println!("{}", hex::encode(&pk[0..32]));
                    }
                }
            }
        }
        Cmd::ScalarCommand(scmd) => {
            #[cfg(feature="donna")] {
                Err("Curve25519tool is built without this feature")?
            }
            #[cfg(feature="dalek")] {
                match scmd.cmd {
                    ScalarCmd::ScalarCanonicalize(x) => {
                        if x.scalaresque.len() > 128 {
                            Err("Scalar value is too big")?;
                        }
                        let b = hex::decode(&x.scalaresque)?;
                        let mut bb = [0u8; 64];
                        bb[0..b.len()].copy_from_slice(&b[..]);
                        let s = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&bb);
                        println!("{}", hex::encode(&s.to_bytes()[..]));
                    }
                    ScalarCmd::ScalarInvert(x) => {
                        let s = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar).ok_or("Non-canonical scalar specified")?;
                        let s = s.invert();
                        println!("{}", hex::encode(&s.to_bytes()[..]));
                        if x.scalar == [0u8; 32] {
                            std::process::exit(1);
                        }
                    }
                    ScalarCmd::ScalarMul(x) => {
                        let s1 = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar1).ok_or("Non-canonical scalar specified")?;
                        let s2 = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar2).ok_or("Non-canonical scalar specified")?;
                        let s = s1 * s2;
                        println!("{}", hex::encode(&s.to_bytes()[..]));
                    }
                    ScalarCmd::ScalarAdd(x) => {
                        let s1 = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar1).ok_or("Non-canonical scalar specified")?;
                        let s2 = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar2).ok_or("Non-canonical scalar specified")?;
                        let s = s1 + s2;
                        println!("{}", hex::encode(&s.to_bytes()[..]));
                    }
                    ScalarCmd::ScalarSub(x) => {
                        let s1 = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar1).ok_or("Non-canonical scalar specified")?;
                        let s2 = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar2).ok_or("Non-canonical scalar specified")?;
                        let s = s1 - s2;
                        println!("{}", hex::encode(&s.to_bytes()[..]));
                    }
                    ScalarCmd::ScalarMontMul(x) => {
                        let s = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar).ok_or("Non-canonical scalar specified")?;
                        let p = curve25519_dalek::montgomery::MontgomeryPoint(x.point);
                        let p2 = p * s;
                        println!("{}", hex::encode(&p2.to_bytes()[..]));
                    }
                    ScalarCmd::ScalarEdMul(x) => {
                        let s = curve25519_dalek::scalar::Scalar::from_canonical_bytes(x.scalar).ok_or("Non-canonical scalar specified")?;
                        let p = curve25519_dalek::edwards::CompressedEdwardsY(x.point);
                        let p = p.decompress().ok_or("Cannot decompress ed25519 point")?;
                        let p2 = p * s;
                        println!("{}", hex::encode(&p2.compress().to_bytes()[..]));
                    }
                    ScalarCmd::EdAdd(x) => {
                        let p1 = curve25519_dalek::edwards::CompressedEdwardsY(x.point1);
                        let p2 = curve25519_dalek::edwards::CompressedEdwardsY(x.point2);
                        let p1 = p1.decompress().ok_or("Cannot decompress ed25519 point")?;
                        let p2 = p2.decompress().ok_or("Cannot decompress ed25519 point")?;
                        let p = p1 + p2;
                        println!("{}", hex::encode(&p.compress().to_bytes()[..]));
                    }
                    ScalarCmd::EdSub(x) => {
                        let p1 = curve25519_dalek::edwards::CompressedEdwardsY(x.point1);
                        let p2 = curve25519_dalek::edwards::CompressedEdwardsY(x.point2);
                        let p1 = p1.decompress().ok_or("Cannot decompress ed25519 point")?;
                        let p2 = p2.decompress().ok_or("Cannot decompress ed25519 point")?;
                        let p = p1 - p2;
                        println!("{}", hex::encode(&p.compress().to_bytes()[..]));
                    }
                }
            }
        }
    }
    Ok(())
}
