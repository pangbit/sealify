#![allow(unused)]

mod aes;
mod rsa;

mod error;

use base64::{engine::general_purpose::STANDARD as StdBase64, Engine};
use chrono::Local;
pub use error::Error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type Result<T> = core::result::Result<T, Error>;

#[derive(Deserialize, Serialize, Debug)]
pub struct License {
    license_type: String,
    user_id: String,
    uuid: String,
    etime: i64,
}

impl License {
    pub fn verify(&self) -> bool {
        Local::now().timestamp_millis() < self.etime
    }

    pub fn r#type(&self) -> &str {
        &self.license_type
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn end_time(&self) -> i64 {
        self.etime
    }
}

pub fn parse_license_key(key: &str, aes_key: &str, rsa_pubkey: &str) -> Result<License> {
    //base64解码
    let key = StdBase64
        .decode(key)
        .map_err(|e| Error::Base64DecodeFailed(e.to_string()))?;

    //aes解密
    let dec = aes::decrypt(aes_key.as_bytes(), &key)?;

    //拆解签名
    let mut items = dec.splitn(2, |b| *b == b'.');
    let data = items.next().ok_or(Error::InvalidLicense)?;
    let signature = items.next().ok_or(Error::InvalidLicense)?;

    //base64解码
    let data = StdBase64
        .decode(data)
        .map_err(|e| Error::Base64DecodeFailed(e.to_string()))?;
    let signature = StdBase64
        .decode(signature)
        .map_err(|e| Error::Base64DecodeFailed(e.to_string()))?;

    //rsa校验签名
    rsa::verify(rsa_pubkey, &data, &signature)?;

    //反序列化
    let license: License =
        serde_json::from_slice(&data).map_err(|e| Error::InvalidLicenseJson(e.to_string()))?;

    Ok(license)
}

pub fn create_license_key(
    license_type: &str,
    user_id: &str,
    etime: i64,
    aes_key: &str,
    rsa_prikey: &str,
) -> String {
    //生成uuid
    let uuid = Uuid::new_v4().to_string();
    //构建license
    let license = License {
        license_type: license_type.to_string(),
        user_id: user_id.to_string(),
        uuid,
        etime,
    };

    //序列化json字符串
    let jstr = serde_json::to_string(&license).expect("license to json failed!");

    //rsa私钥签名
    let signature =
        StdBase64.encode(rsa::sign(rsa_prikey, jstr.as_bytes()).expect("rsa sign failed!"));

    //拼接license key
    let mut key = StdBase64.encode(&jstr);
    key.push('.');
    key.push_str(&signature);

    //aes加密 & base64编码
    let enc_key = aes::encrypt(aes_key.as_bytes(), key.as_bytes()).unwrap();
    StdBase64.encode(enc_key)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine;
    use chrono::{FixedOffset, NaiveDate};

    use super::*;

    const AESKEY: &'static str = "x8WfNHpmhNdLZLiuV1YzlqeLBcJGPQuW";
    const RSA_PUBKEY: &'static str = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA98eK6hOtveMQLKQnd/JT
1EdwN8x/Ca8VNXlNOuTKlRaG21OgbjoYdfm4ojOJUkHjKL8kbhBhKs9tXIyGDZuc
uxj3vXO82v+QVpq4Wde94FBGYRjO65xvIM2QrIbyr6eWYqhKvzN3VoiyA/isSkAb
79agZ/y5lD+IWJSJgZt41UrG4VUVhidnxOeB9ldMSUu4SQKLKGlYM8o9FzKDApyw
f4azdiIgGKWwta5B33K5PfS7ubNS1/D1/ol2FTCc9imsTmm7K2SnOi6dDM9n1j+E
1yquGhVs7i9/kmBZ7wk/ehi7/igNOyNUjrh1jhW/1HY2RL3X52MEjhE+Foq9+Sn3
lwIDAQAB
-----END PUBLIC KEY-----";
    const RSA_PRIKEY: &'static str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD3x4rqE6294xAs
pCd38lPUR3A3zH8JrxU1eU065MqVFobbU6BuOhh1+biiM4lSQeMovyRuEGEqz21c
jIYNm5y7GPe9c7za/5BWmrhZ173gUEZhGM7rnG8gzZCshvKvp5ZiqEq/M3dWiLID
+KxKQBvv1qBn/LmUP4hYlImBm3jVSsbhVRWGJ2fE54H2V0xJS7hJAosoaVgzyj0X
MoMCnLB/hrN2IiAYpbC1rkHfcrk99Lu5s1LX8PX+iXYVMJz2KaxOabsrZKc6Lp0M
z2fWP4TXKq4aFWzuL3+SYFnvCT96GLv+KA07I1SOuHWOFb/UdjZEvdfnYwSOET4W
ir35KfeXAgMBAAECggEAdMHgocC4JDx1CLQprQnRmrw3EvQYANYx5krMq63YEDzX
O07C0G4rzJvp9vTWBp7pje/UGNE7GFM6M1w8Zvkm97siMnHxUjkPKOArcpqI7MSn
BWYNS1UhwJFdVQ8aGM+du8uVvVdhKrOrPtfVR//Bqli2qYmbYVI2y5bi3OIIJGj0
xMSJfUpd49uygRzbBI4GRTCYsiHWNiinagej7ERFQkWYMJpargvOJyU5Z/vMy9yG
3Qe5ysZFQ9ffo8j42XtkQ3KDp/0sTBMNlHP1PVwxq5RNKwOK/ZEAnAyKPWPyPP6Z
zRmwFVgwGnE9BV46GHbz1rSiXBLTQqTkLFp5TBbsAQKBgQD6FeHGSJrHwyM+KZz+
Fs/u/vzH431fDfK7dIrCgAj4Ie6U+jfR46P40kkKPCsIDe1of6iCtZO21KKxtGBd
LAaXO5XXN9bciYgzpS6Y4URson+g+ZYpqZgD8W6RqTC1ZYJWoye8uAR+OwlOJRHL
1PEU49EXSC5knE9nfS7UMZrBAQKBgQD9o7L8/gTUz1YGyAqIA44/q+HvnNZI5NxR
YlXvELnOfpAwvHQmtkVgZEmbu7U1RvabcxYleuFZilEcUTlSuCWFhgfGOHvEi54P
BNYYvX6s6CN+RPLvohDGcSuO/f1qKFfNffzW8dWYP76tMxsipXgyMVrlY4bt/Ls7
o6H/HMIglwKBgQCdI/rF+QEo3HjcqpE3J2Zoqlhz0YIJpF4NY+F87a61G70qZz+D
5yI1Sw0SHVR8ryOqMezUlPvIOjwwpUKXyP4rMQmqPjAIS3MF4Jky/vlbuY+wuqOc
cjBO6fmsFT/B+5K2lbZ2YrqQBtCGBcz040zI742Gr5hXJ9DNGl++fZzcAQKBgBnn
Lu9hbdLh/dIhedncKxnbju5uoP++x7VUCpyoo6EwEb+4b1BIyxsGAvJxoBb50VOc
1EUtoHgJhTEUJnuJLOPPBVo8CH/RFmpIPyk1qQs1hfJuTjUk4vuxMRagX9IInrbw
x/KXrg2nbOy5TGskZPsTSUol+PCzH9f+ZRvtrvGvAoGBAOBXjJZsgpQiGB9AY/ar
JcK7C/47suJlDgA+bXAhV5ytaWIhHSp9ekS0eOca2IuQLy3O5gfeiz3+5PaYYSv7
LEf1zfOhIWrLo7iBc88eFxx7AWojWlwon8ulgFwcOwzabF3JPyuCH/LnvzVuaASk
S8OJrL5SjTxZPKEneMZsaMex
-----END PRIVATE KEY-----";

    #[test]
    fn test_license_parse() {
        let key = "ss7vKLoQyLTckiDpq1V5ShkhtBYTsZdWrEp6Cfni57vA1DrFpUvIHDMmERxCaNi1HCERl4Iul5wW2HXEy1eA0SJPwvhHTHcZAdxiptEme3gCeDgMeW/1oTZYpWP2OQXB7Akawc0a6vhUhJj9prn9LlgFx2lun/Xx5MKmy03Ogg3FOfV6idxZ5McDTQA+IwL0egJQ2qKTJJv+Mh4LJ2byu42E8CMD/pgwmYnKtz/UTzIiLDpYrjt3yUw17Ps+peTRYHiYWbyDFuJ7WgABlsXJ4GTZcBnShiNwp8xnCCclpTHTANBgznxTGgbmt8mHULoPstMzdlnoY8etKH6+jj+18CX71OyE2tnQlBVzT2Q4SX7Pj+xHqX4OCsXA7I+KqVm3V9wR9u/MiqxXo3WfPscJjeBfW4Uneh53XYiPJUuK2dft2RIFOm0jvUn+NfLfasK3ldSG6pS2X1OrcRr14cHjyB6ahXFFm91Y2m4EXODCki8n6S2fQFNIxIEq6e/oh85ZYcvqvUUBs5xQYkiEwvKTsXVuzjXyhW6uoi765uthJsrqUrVLNu13+oZZcBKpaMyeM+sqnbS1aIyQqaiNqWQtZwpU7bwfmGym0OkK7ADhlssuQljrsy+xjsdVn8vDIqrOnKv73OYcgm2SqzxJKEZNhkR++99/2j/Z4OzJF5/zn9A6wrkt9xdf6s5EMnfWcYEpbwo/NXiOAKv/omUBctC4XuQttOI2WQBHAcfpfJWBOtOI";

        let license = parse_license_key(key, &AESKEY, &RSA_PUBKEY).unwrap();
        println!("{:?}", license);
    }

    #[test]
    fn test_gen_license() {
        let license = License {
            license_type: "full".to_string(),
            user_id: "b99fffd0-acc7-4ac2-adca-71465ea55ecd".to_string(),
            uuid: "08dddb08-d018-46a6-aa77-5a0a95149d3e".to_string(),
            etime: 4102416000000,
        };

        let jstr = serde_json::to_string(&license).unwrap();
        println!("JSON: {}", jstr);

        let bstr = base64::engine::general_purpose::STANDARD.encode(&jstr);
        println!("BASE64: {}", bstr);

        let signature = rsa::sign(&RSA_PRIKEY, jstr.as_bytes()).unwrap();
        let signature = base64::engine::general_purpose::STANDARD.encode(signature);
        println!("SIGNATURE: {}", signature);

        let key = format!("{}.{}", bstr, signature);

        let enc_key = aes::encrypt(AESKEY.as_bytes(), key.as_bytes()).unwrap();
        let enc_key = base64::engine::general_purpose::STANDARD.encode(enc_key);
        println!("ENC_KEY: {}", enc_key);
    }

    #[test]
    fn gen_uuid() {
        println!("{}", Uuid::new_v4().to_string());
        println!("{}", Uuid::new_v4().to_string());
        println!("{}", Uuid::new_v4().to_string());
        println!("{}", Uuid::new_v4().to_string());
        println!("{}", Uuid::new_v4().to_string());
        println!("{}", Uuid::new_v4().to_string());
    }

    #[test]
    fn test_license() {
        let etime = NaiveDate::from_ymd_opt(2025, 12, 31)
            .expect("invalid date")
            .and_hms_opt(0, 0, 0)
            .expect("invalid time")
            .and_utc()
            .timestamp();

        let license_key = create_license_key("full", "1", etime, AESKEY, RSA_PRIKEY);
        assert!(parse_license_key(&license_key, AESKEY, RSA_PUBKEY).is_ok());

        let license_key = create_license_key("waf,bot", "2", etime, AESKEY, RSA_PRIKEY);
        assert!(parse_license_key(&license_key, AESKEY, RSA_PUBKEY).is_ok());

        let license_key = create_license_key("bot,cc", "3", etime, AESKEY, RSA_PRIKEY);
        assert!(parse_license_key(&license_key, AESKEY, RSA_PUBKEY).is_ok());

        let license_key = create_license_key("waf,cc", "4", etime, AESKEY, RSA_PRIKEY);
        assert!(parse_license_key(&license_key, AESKEY, RSA_PUBKEY).is_ok());

        let license_key = create_license_key("waf,bot,cc", "5", etime, AESKEY, RSA_PRIKEY);
        assert!(parse_license_key(&license_key, AESKEY, RSA_PUBKEY).is_ok());
    }
}
