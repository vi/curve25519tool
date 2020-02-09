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
}

/// Verify signature of data supplied to stdin
#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
struct Verify {
    #[argh(positional,from_str_fn(readhex32))]
    pubkey: [u8; 32],

    #[argh(positional,from_str_fn(readhex64))]
    signature: [u8; 64],
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
                let signat = sign(&pkbuf,&buf[..],&rnd).ok_or("sign failed")?;
                println!("{}", hex::encode(&signat[..]));
            }
            #[cfg(feature="dalek")] {
                let mut pkbuf2 = [0u8; 64];
                pkbuf2[0..32].copy_from_slice(&pkbuf[..]);
                pkbuf2[32..64].copy_from_slice(&rnd[0..32]);
                let pk = EdSecretKey::from_bytes(&pkbuf2[..]).unwrap();
                

                let pubk = PublicKey::from(&StaticSecret::from(pkbuf));
                let pubk = curve25519_dalek::montgomery::MontgomeryPoint(*pubk.as_bytes());
                let pubk = pubk.to_edwards(0).unwrap().compress();
                let pubk = EdPublicKey::from_bytes(pubk.as_bytes()).unwrap();

                let s = pk.sign::<sha2::Sha512>(&buf[..], &pubk);
                println!("{}", hex::encode(&s.to_bytes()[..]));
            }
        }
        Cmd::Verify(v) => {
            let mut buf = Vec::with_capacity(4096);
            std::io::stdin().read_to_end(&mut buf)?;

            #[cfg(feature="donna")] {
                if ! verify(&v.signature, &v.pubkey, &buf[..]) {
                    Err("Signature verification failed")?;
                }
            }
            #[cfg(feature="dalek")] {
                let mut sbuf = v.signature;
                let sign = if sbuf[63] & 0x80 != 0 {
                    sbuf[63] &= 0x7F;
                    1
                } else {
                    0
                };
                let s = Signature::from_bytes(&sbuf[..]).map_err(|e|format!("{}",e))?;
                let pk = curve25519_dalek::montgomery::MontgomeryPoint(v.pubkey);
                let pk = pk.to_edwards(sign).unwrap().compress();
                let pk = EdPublicKey::from_bytes(pk.as_bytes()).unwrap();
                if let Err(_) = pk.verify::<sha2::Sha512>(&buf[..], &s) {
                    Err("Signature verification failed")?;
                }
            }
        }
    }
    Ok(())
}
