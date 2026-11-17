import asyncio
import time
import httpx
import json
import threading
import random
import binascii
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, make_response, Response
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
import jwt as pyjwt
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2, GetWishListItems_pb2
from proto import MajoRLoGinrEs_pb2
from proto import RemoveFriend_Req_pb2, uid_generator_pb2
from proto import ReqCLan_pb2, QuitClanReq_pb2
from proto import nick_data_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as crypto_pad
import base64
import os
import sys
import ssl
import gzip
import http.client
import urllib3
import requests
from io import BytesIO
import datetime
from datetime import datetime as dt, timezone, timedelta, time as dt_time
from byte import Encrypt_ID, encrypt_api
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logging.basicConfig(level=logging.INFO)


MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

REGION_PRIORITY = ["ME", "IND", "BR"]

REGION_BASE_URLS = {
    "IND": ["https://client.ind.freefiremobile.com"],
    "BR":  ["https://client.us.freefiremobile.com"],
    "US":  ["https://client.us.freefiremobile.com"],
    "SAC": ["https://client.us.freefiremobile.com"],
    "NA":  ["https://client.us.freefiremobile.com"],
}
DEFAULT_BASE_URLS = [
    "https://clientbp.ggpolarbear.com",
    "https://clientbp.ppmainecoonghj.com",
]

FREEFIRE_UPDATE_URL = "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"
BIO_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
BIO_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

ICON_API_URL = "https://star-icon-png.lovable.app/png?icon_id={}"
BACKGROUND_FILENAME = "shappno.png"
IMAGE_REQUEST_TIMEOUT = 15


app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=200, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}


def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def _candidate_servers(region: str, major_server: str):
    candidates = []
    if major_server:
        candidates.append(major_server.rstrip("/"))
    r = (region or "").upper()
    for url in REGION_BASE_URLS.get(r, []):
        if url not in candidates:
            candidates.append(url)
    for url in DEFAULT_BASE_URLS:
        if url not in candidates:
            candidates.append(url)
    return candidates


def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=5896577295&password=shappno_GPs6fx7m"
    elif r == "ME":
        return "uid=5845633224&password=shappno_bqKurBcU"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=5119668284&password=57A9EF8FD80654681B3C6E806EB6CF94187D236A735DFF3AF0EBA638748EF5E0"
    else:
        return "uid=5845633224&password=shappno_bqKurBcU"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MajorLoginHost = "loginbp.ppmainecoonghj.com"
MajorLoginPath = "/MajorLogin"
FreeFireVersion = "OB55"
GUEST_URL = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
CLIENT_ID = 100067
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
JWT_AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
JWT_AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
RESPONSE_HEADER_LEN = 64

def _jwt_encode_varint(num: int) -> bytes:
    if num < 0:
        raise ValueError("Number must be non-negative")
    out = []
    while True:
        b = num & 0x7F
        num >>= 7
        if num:
            b |= 0x80
        out.append(b)
        if not num:
            break
    return bytes(out)

def _jwt_create_field(num, val):
    if isinstance(val, bool):
        return _jwt_encode_varint((num << 3) | 0) + _jwt_encode_varint(int(val))
    if isinstance(val, int):
        return _jwt_encode_varint((num << 3) | 0) + _jwt_encode_varint(val)
    if isinstance(val, (str, bytes)):
        v = val.encode() if isinstance(val, str) else val
        return _jwt_encode_varint((num << 3) | 2) + _jwt_encode_varint(len(v)) + v
    if isinstance(val, dict):
        nested = _jwt_create_packet(val)
        return _jwt_encode_varint((num << 3) | 2) + _jwt_encode_varint(len(nested)) + nested
    return b""

def _jwt_create_packet(fields: dict) -> bytes:
    return b"".join(_jwt_create_field(k, v) for k, v in fields.items())

def _jwt_encrypt_api(plain: bytes) -> bytes:
    cipher = AES.new(JWT_AES_KEY, AES.MODE_CBC, JWT_AES_IV)
    pad_len = AES.block_size - (len(plain) % AES.block_size)
    return cipher.encrypt(plain + bytes([pad_len] * pad_len))

def _jwt_decrypt_response(data: bytes) -> bytes:
    try:
        cipher = AES.new(JWT_AES_KEY, AES.MODE_CBC, JWT_AES_IV)
        dec = cipher.decrypt(data)
        pad_len = dec[-1]
        if 1 <= pad_len <= 16 and all(b == pad_len for b in dec[-pad_len:]):
            dec = dec[:-pad_len]
        return dec
    except Exception:
        return b""

def _jwt_decode_response(resp: bytes):
    def try_parse(blob):
        if not blob:
            return None
        try:
            msg = MajoRLoGinrEs_pb2.MajorLoginRes()
            msg.ParseFromString(blob)
            if msg.account_id > 0 and (msg.lock_region or msg.noti_region or msg.token):
                return msg
        except Exception:
            pass
        return None
    msg = try_parse(resp)
    if msg:
        return msg, "plaintext proto"
    if len(resp) > RESPONSE_HEADER_LEN:
        msg = try_parse(resp[RESPONSE_HEADER_LEN:])
        if msg:
            return msg, "plaintext proto (skip signature)"
    if len(resp) >= 16 and len(resp) % 16 == 0:
        dec = _jwt_decrypt_response(resp)
        msg = try_parse(dec) if dec else None
        if msg:
            return msg, "AES-CBC"
        if dec and len(dec) > RESPONSE_HEADER_LEN:
            msg = try_parse(dec[RESPONSE_HEADER_LEN:])
            if msg:
                return msg, "AES-CBC (skip signature)"
    return None, "unknown"

def _jwt_decode_token(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except Exception:
        return {}

def _jwt_build_login_body(access_token, open_id, region="BD", lang="bn"):
    fields = {
        3: dt.now().strftime("%Y-%m-%d %H:%M:%S"), 4: "free fire", 5: 1,
        7: "1.132.4",
        8: "Android OS 15 / API-35 (AP3A.240617.008/T.R4T2.24e2a71-650ec)",
        9: "Handheld", 10: "airtel now cirkle", 11: "WIFI", 12: 1666,
        13: 750, 14: "360", 15: "ARM64 FP ASIMD AES | 2000 | 8",
        16: 7723, 17: "Mali-G52 MC2",
        18: "OpenGL ES 3.2 v1.r49p1-03bet0.19498e0ae1d5dac223383c39a2e58f04",
        19: "Google|3744f365-78fe-424a-871e-f77a0a095356", 20: "103.109.214.50",
        21: lang, 22: open_id, 23: "8", 24: "Handheld", 25: "realme RMX3710",
        26: region, 29: access_token, 30: 1, 41: "airtel now cirkle",
        42: "WIFI", 57: "7428b253defc164018c604a1ebbfebdf",
        60: 225554, 61: 155321, 62: 733, 64: 155845, 65: 225554,
        66: 155845, 67: 225554, 73: 2,
        74: "/data/app/~~ln8dFa29BUuPBtG4A-WwXQ==/com.dts.freefireth-tXx7bnxvKbykwJzwnEHs2Q==/lib/arm64",
        76: 1,
        77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~ln8dFa29BUuPBtG4A-WwXQ==/com.dts.freefireth-tXx7bnxvKbykwJzwnEHs2Q==/base.apk",
        78: 3, 79: 2, 81: "64", 83: "2019121229", 85: 3, 86: "OpenGLES2",
        87: 8191, 88: 8, 92: 9754, 93: "android",
        94: "KqsHT+PFj/2sTPjf+unI9C5rnnStUzOFVqOADw9TI8tgL2bTnmzrBM/dEzyqy4BtAVua+w9mgLRIMrjXa67/qXm0pz5uQWsxC6sd8Um7OmMNHRmy",
        95: 111207, 96: '{"cur_rate":[60,45,90],"support_etc2":false}',
        97: 1, 99: "4", 100: "4", 102: "4455414f055f5f0336", 104: 52972,
        105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    return _jwt_create_packet(fields)

def get_user_access_token(uid, password):
    headers = {
        "User-Agent": "GarenaMSDK/4.0.42(M2006C3LII ;Android 10;en;IN;app 1.126.2 2019120816;)",
        "Accept": "application/json", "Content-Type": "application/json; charset=utf-8",
        "Connection": "Keep-Alive",
    }
    payload = {
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "client_type": 2,
        "password": password, "response_type": "token", "uid": int(uid),
    }
    try:
        response = requests.post(GUEST_URL, headers=headers, json=payload,
                                 verify=False, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("code") == 0:
                result = data.get("data", {}) or {}
                return result.get("access_token"), result.get("open_id")
            print(f"[oauth] {response.status_code}")
        else:
            print(f"[oauth] {response.status_code}")
    except Exception:
        print("[oauth] err")
    return None, None

def major_login_request(access_token, open_id, region="BD", lang="bn"):
    try:
        plain = _jwt_build_login_body(access_token, open_id, region, lang)
        body = _jwt_encrypt_api(plain)
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(MajorLoginHost, context=ctx, timeout=3)
        conn.request("POST", MajorLoginPath, body=body, headers={
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
            "Authorization": "Bearer", "X-Ga": "v1 1", "X-Ga-Sv": "1789556611",
            "Releaseversion": FreeFireVersion,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1",
        })
        response = conn.getresponse()
        raw = response.read()
        encoding = response.getheader("Content-Encoding")
        conn.close()
        if encoding == "gzip":
            with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
                raw = stream.read()
        if response.status in (200, 201):
            return raw, None
        return None, f"HTTP {response.status}"
    except Exception as exc:
        return None, str(exc)

def create_user_jwt(uid, password, region="BD", lang="bn", return_open_id=False):
    """Create one OAuth token, then race the supported JWT regions in parallel."""
    access_token, open_id = get_user_access_token(uid, password)
    if not access_token or not open_id:
        return (None, None, "OAuth failed", None) if return_open_id else (None, None, "OAuth failed")

    preferred = (region or "BD").upper()
    region_order = [preferred] + [r for r in ("BD", "ME", "IND", "BR") if r != preferred]
    # Region requests are independent after OAuth. Starting them together avoids
    # serial 3-second network waits when a region is unavailable.
    executor = ThreadPoolExecutor(max_workers=len(region_order))
    futures = {
        executor.submit(major_login_request, access_token, open_id, r, lang): r
        for r in region_order
    }
    last_error = "JWT generation failed"
    try:
        for future in as_completed(futures):
            try:
                raw, err = future.result()
                if not raw:
                    last_error = err or last_error
                    continue
                result, mode = _jwt_decode_response(raw)
                if result and result.token:
                    for pending in futures:
                        if pending is not future:
                            pending.cancel()
                    return (result, access_token, None, open_id) if return_open_id else (result, access_token, None)
                last_error = f"No JWT token ({mode})"
            except Exception as exc:
                last_error = str(exc)
    finally:
        # Do not hold up the HTTP response for slower, already-unneeded regions.
        executor.shutdown(wait=False, cancel_futures=True)

    return (None, access_token, last_error, open_id) if return_open_id else (None, access_token, last_error)

def create_jwt_from_access_token(access_token, region="BD", lang="bn"):
    try:
        open_id = None
        try:
            parts = access_token.split(".")
            if len(parts) == 3:
                payload = parts[1] + "=" * (-len(parts[1]) % 4)
                data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
                open_id = data.get("open_id") or data.get("sub")
        except Exception:
            pass
        return None, "need_uid"
    except Exception as e:
        return None, str(e)


async def create_jwt(region: str):
    try:
        account = get_account_credentials(region)
        parts = dict(item.split("=", 1) for item in account.split("&") if "=" in item)
        result, _, error = await asyncio.to_thread(
            create_user_jwt, parts.get("uid", ""), parts.get("password", ""),
            region=region, lang="bn"
        )
        if error or not result:
            raise RuntimeError(error or "JWT generation failed")
        cached_tokens[region] = {
            "token": f"Bearer {result.token}",
            "region": result.lock_region or region,
            "server_url": result.server_url,
            "expires_at": time.time() + min(result.ttl or 25200, 25200)
        }
        print(f"[token] {region} ok")
    except Exception:
        print(f"[token] {region} fail")


async def initialize_tokens():
    pass

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        for r in list(cached_tokens.keys()):
            try:
                await create_jwt(r)
            except Exception:
                pass

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info.get('expires_at', 0):
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens.get(region) or {}
    if not info.get('token'):
        await create_jwt(region)
        info = cached_tokens.get(region) or {}
    return info.get('token', ''), info.get('region', ''), info.get('server_url', '')



async def _fetch_endpoint(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, major_server = await get_token_info(region)

    if not token:
        raise Exception(f"Token not available for region {region}")

    headers = {
        'User-Agent': USERAGENT,
        'Authorization': token,
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
    }

    candidates = _candidate_servers(region, major_server)
    last_error = None
    resp_content = None

    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        for base in candidates:
            url = base.rstrip("/") + endpoint
            try:
                resp = await client.post(url, content=data_enc, headers=headers)
            except Exception:
                last_error = f"{base}: err"
                continue
            if resp.status_code == 200 and resp.content:
                resp_content = resp.content
                last_error = None
                break
            else:
                last_error = f"{base}: {resp.status_code}"

    if resp_content is None:
        raise Exception(f"All servers failed for {region}{endpoint}: {last_error}")

    try:
        res_data = json.loads(json_format.MessageToJson(
            decode_protobuf(resp_content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
    except Exception as pe:
        raise Exception(f"Decode error: {pe}")

    detected_region = (res_data.get('basicInfo', {}) or {}).get('region', '').upper()
    if (detected_region == "IND" or lock == "IND") and region != "IND":
        uid_region_cache[uid] = "IND"
        token2, _, major2 = await get_token_info("IND")
        if token2:
            headers['Authorization'] = token2
            async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
                for base in _candidate_servers("IND", major2):
                    try:
                        resp = await client.post(base.rstrip("/") + endpoint,
                                                 content=data_enc, headers=headers)
                        if resp.status_code == 200 and resp.content:
                            res_data = json.loads(json_format.MessageToJson(
                                decode_protobuf(resp.content,
                                                AccountPersonalShow_pb2.AccountPersonalShowInfo)))
                            break
                    except Exception:
                        continue
    return res_data


async def GetAccountInformation(uid, unk, region, endpoint, allow_reroute=True):
    return await _fetch_endpoint(uid, unk, region, endpoint)



async def GetWishList(uid, region):
    req = GetWishListItems_pb2.CSGetWishListItemsReq()
    req.account_id = int(uid)
    req_json = json_format.MessageToJson(req)
    payload = await json_to_proto(req_json, GetWishListItems_pb2.CSGetWishListItemsReq())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    token, lock, major_server = await get_token_info(region)
    if not token:
        raise Exception(f"Token not available for {region}")

    headers = {
        'User-Agent': USERAGENT,
        'Authorization': token,
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
    }

    candidates = _candidate_servers(region, major_server)
    last_error = None
    resp_content = None

    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        for base in candidates:
            url = base.rstrip("/") + "/GetWishListItems"
            try:
                resp = await client.post(url, content=data_enc, headers=headers)
            except Exception:
                last_error = f"{base}: err"
                continue
            if resp.status_code == 200 and resp.content:
                resp_content = resp.content
                last_error = None
                break
            else:
                last_error = f"{base}: {resp.status_code}"

    if resp_content is None:
        raise Exception(f"Wishlist servers failed for {region}: {last_error}")

    res = GetWishListItems_pb2.CSGetWishListItemsRes()
    res.ParseFromString(resp_content)
    return json.loads(json_format.MessageToJson(res))



def get_br_rank_name(rp):
    try:
        rp = int(rp)
    except:
        return "N/A"
    if rp <= 999:
        if rp <= 0: return "Bronze I"
        if rp < 100: return "Bronze II"
        if rp < 200: return "Bronze III"
        if rp < 300: return "Silver I"
        if rp < 400: return "Silver II"
        if rp < 500: return "Silver III"
        if rp < 600: return "Gold I"
        if rp < 700: return "Gold II"
        if rp < 800: return "Gold III"
        if rp < 900: return "Gold IV"
        return "Platinum I"
    if rp < 1300: return "Silver I"
    if rp < 1400: return "Silver II"
    if rp < 1500: return "Silver III"
    if rp < 1600: return "Gold I"
    if rp < 1725: return "Gold I"
    if rp < 1850: return "Gold II"
    if rp < 1975: return "Gold III"
    if rp < 2100: return "Gold IV"
    if rp < 2225: return "Platinum I"
    if rp < 2350: return "Platinum II"
    if rp < 2475: return "Platinum III"
    if rp < 2600: return "Platinum IV"
    if rp < 2750: return "Platinum V"
    if rp < 2900: return "Diamond I"
    if rp < 3050: return "Diamond II"
    if rp < 3200: return "Diamond III"
    if rp < 3350: return "Diamond IV"
    if rp < 3500: return "Diamond V"
    if rp < 3800: return "Heroic"
    if rp < 4300: return "Heroic"
    if rp < 4900: return "Elite Heroic"
    if rp < 5500: return "Elite Heroic"
    if rp < 6300: return "Elite Heroic"
    if rp < 7100: return "Master"
    if rp < 8000: return "Master"
    if rp < 9000: return "Elite Master"
    return "Elite Master"

def get_br_rank_with_score(rp):
    try:
        return f"{get_br_rank_name(int(rp))} ({int(rp)})"
    except:
        return "N/A"

def get_cs_rank_name(rp):
    try:
        rp = int(rp)
    except:
        return "N/A"
    if rp <= 0: return "Bronze I"
    if rp < 100: return "Bronze I"
    if rp < 200: return "Bronze II"
    if rp < 300: return "Bronze III"
    if rp < 400: return "Silver I"
    if rp < 500: return "Silver II"
    if rp < 600: return "Silver III"
    if rp < 700: return "Gold I"
    if rp < 800: return "Gold II"
    if rp < 900: return "Gold III"
    if rp < 1000: return "Gold IV"
    if rp < 1100: return "Platinum I"
    if rp < 1200: return "Platinum II"
    if rp < 1300: return "Platinum III"
    if rp < 1400: return "Platinum IV"
    if rp < 1500: return "Platinum V"
    if rp < 1600: return "Diamond I"
    if rp < 1700: return "Diamond II"
    if rp < 1800: return "Diamond III"
    if rp < 1900: return "Diamond IV"
    if rp < 2000: return "Diamond V"
    if rp < 2500: return "Heroic"
    if rp < 3000: return "Elite Heroic"
    if rp < 3500: return "Master"
    return "Elite Master"

def get_cs_rank_with_score(rp):
    try:
        return f"{get_cs_rank_name(int(rp))} ({int(rp)})"
    except:
        return "N/A"

def add_rank_info(data):
    try:
        for k in ('basicInfo', 'captainBasicInfo'):
            block = data.get(k, {})
            if block:
                block['rank_name'] = get_br_rank_with_score(block.get('rankingPoints', 0))
                block['cs_rank_name'] = get_cs_rank_with_score(block.get('csRankingPoints', 0))
    except:
        pass
    return data

def format_timestamp_bst(timestamp):
    try:
        dt_obj = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
        bst = timezone(timedelta(hours=6))
        return dt_obj.astimezone(bst).strftime("%d %B %Y at %I:%M:%S %p") + " (BST)"
    except:
        return "Unknown"



def find_best_region(uid):
    if uid in uid_region_cache:
        return uid_region_cache[uid]

    for region in REGION_PRIORITY:
        if region not in SUPPORTED_REGIONS:
            continue
        try:
            tok, _, _ = asyncio.run(get_token_info(region))
            if not tok:
                continue
            data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            basic = data.get('basicInfo', {}) or {}
            if basic.get('accountId'):
                real = (basic.get('region') or region).upper()
                uid_region_cache[uid] = real
                return real
        except Exception:
            continue
    return None

def resolve_region(uid, force_region=None):
    if force_region and force_region.upper() in SUPPORTED_REGIONS:
        r = force_region.upper()
        uid_region_cache[uid] = r
        return r
    return find_best_region(uid)

def add_equipped_items(data):
    try:
        basic = data.get('basicInfo', {})
        if basic:
            basic['equipped_items'] = {
                "weapon_skins": basic.get('weaponSkinShows', []),
                "pin_id": basic.get('pinId', 0),
                "banner_id": basic.get('bannerId', 0),
                "head_pic": basic.get('headPic', 0),
                "title": basic.get('title', 0),
                "badge_id": basic.get('badgeId', 0),
                "equipped_animation_id": basic.get('equippedAnimationId', 0)
            }
        profile = data.get('profileInfo', {})
        if profile:
            profile['equipped_items'] = {
                "avatar_id": profile.get('avatarId', 0),
                "skin_color": profile.get('skinColor', 0),
                "clothes": profile.get('clothes', []),
                "equipped_skills": profile.get('equipedSkills', []),
                "is_selected": profile.get('isSelected', False),
                "is_selected_awaken": profile.get('isSelectedAwaken', False),
                "equipped_animation_id": profile.get('equippedAnimationId', 0)
            }
        captain = data.get('captainBasicInfo', {})
        if captain:
            captain['equipped_items'] = {
                "weapon_skins": captain.get('weaponSkinShows', []),
                "pin_id": captain.get('pinId', 0),
                "banner_id": captain.get('bannerId', 0),
                "head_pic": captain.get('headPic', 0),
                "title": captain.get('title', 0),
                "badge_id": captain.get('badgeId', 0),
                "equipped_animation_id": captain.get('equippedAnimationId', 0)
            }
    except Exception:
        pass
    return data

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(sorted(request.args.items())))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator


def _bio_enc_var(number: int) -> bytes:
    encoded = bytearray()
    while number > 127:
        encoded.append((number & 127) | 128)
        number >>= 7
    encoded.append(number)
    return bytes(encoded)


def _bio_enc_proto(field_map: dict) -> bytes:
    protobuf_bytes = b""
    for field_number, field_value in field_map.items():
        if isinstance(field_value, int):
            protobuf_bytes += _bio_enc_var((field_number << 3) | 0)
            protobuf_bytes += _bio_enc_var(field_value)
        elif isinstance(field_value, str):
            value_bytes = field_value.encode("utf-8")
            protobuf_bytes += _bio_enc_var((field_number << 3) | 2)
            protobuf_bytes += _bio_enc_var(len(value_bytes)) + value_bytes
        elif isinstance(field_value, bytes):
            protobuf_bytes += _bio_enc_var((field_number << 3) | 2)
            protobuf_bytes += _bio_enc_var(len(field_value)) + field_value
        else:
            raise TypeError(
                f"Unsupported bio field {field_number}: {type(field_value).__name__}"
            )
    return protobuf_bytes


def _bio_encrypt(data_bytes: bytes) -> bytes:
    cipher = AES.new(BIO_KEY, AES.MODE_CBC, BIO_IV)
    return cipher.encrypt(crypto_pad(data_bytes, AES.block_size))


def _upload_bio(jwt_token: str, bio_text: str):
    try:
        payload = {
            2: 1,
            5: "",
            6: "",
            8: bio_text,
            11: "",
            12: "",
            16: "",
        }
        encrypted_body = _bio_encrypt(_bio_enc_proto(payload))
        headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip",
            "X-GA-SV": "1794472840",
            "Authorization": f"Bearer {jwt_token}",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1",
            "Content-Length": str(len(encrypted_body)),
        }
        response = requests.post(
            FREEFIRE_UPDATE_URL,
            headers=headers,
            data=encrypted_body,
            timeout=30,
            verify=False,
        )
        return response.status_code, response.content
    except Exception as exc:
        return 500, str(exc).encode("utf-8")


def _bio_decode_nickname(encoded: str) -> str:
    try:
        SECRET = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ SECRET[i % len(SECRET)])
        return dec.decode('utf-8', errors='replace')
    except Exception:
        return encoded


def _decode_jwt_info(token: str):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None
        payload_b64 = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        uid = payload.get("account_id")
        region = payload.get("lock_region")
        nickname = payload.get("nickname")
        if isinstance(nickname, str):
            nickname = _bio_decode_nickname(nickname)
        return str(uid) if uid else None, nickname, region
    except Exception:
        return None, None, None


def _get_jwt_via_uid_pass(uid: str, password: str, region_hint: str = None):
    # create_user_jwt already tries BD/ME/IND/BR concurrently. Calling it once
    # avoids repeating the same four-region fallback for each outer region.
    preferred = region_hint.upper() if region_hint and region_hint.upper() in SUPPORTED_REGIONS else "BD"
    try:
        result, access_token, error = create_user_jwt(uid, password, region=preferred)
        if error or not result:
            return {"error": error or "JWT generation failed"}
        return {
            "token": result.token,
            "access_token": access_token,
            "region": result.lock_region or preferred,
            "server_url": result.server_url,
        }
    except Exception as exc:
        return {"error": str(exc)}

def _get_jwt_via_access_token(access_token: str, region_hint: str = None):
    open_id = None
    try:
        parts = access_token.split(".")
        if len(parts) == 3:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
            open_id = data.get("open_id") or data.get("sub")
    except Exception:
        pass

    if open_id:
        order = []
        if region_hint and region_hint.upper() in SUPPORTED_REGIONS:
            order.append(region_hint.upper())
        for r in REGION_PRIORITY:
            if r not in order:
                order.append(r)

        last_err = None
        for r in order:
            raw, error = major_login_request(access_token, open_id, region=r)
            if not raw:
                last_err = error or "MajorLogin failed"
                continue
            result, mode = _jwt_decode_response(raw)
            if result and result.token:
                return {
                    "token": result.token,
                    "access_token": access_token,
                    "region": result.lock_region or r,
                    "server_url": result.server_url,
                }
            last_err = f"No JWT token ({mode})"
        return {"error": last_err or "MajorLogin failed"}

    return {
        "token": access_token,
        "access_token": access_token,
        "region": region_hint or "ME",
        "server_url": None,
        "opaque": True,
    }


@app.route("/bio_upload", methods=["GET", "POST"])
def bio_upload_endpoint():
    bio = request.args.get("bio") or request.form.get("bio")
    if not bio:
        return jsonify({"status": "error", "code": 400,
                        "error": "Missing 'bio' parameter"}), 400

    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = (request.args.get("pass") or request.args.get("password")
                or request.form.get("pass") or request.form.get("password"))
    access = request.args.get("access") or request.form.get("access")
    region_hint = request.args.get("region") or request.form.get("region")

    final_jwt = None
    login_method = None
    final_access_token = None
    final_open_id = None
    final_uid = None
    final_name = None
    final_region = None

    if jwt_token:
        login_method = "Direct JWT"
        final_jwt = jwt_token
        u, name, reg = _decode_jwt_info(jwt_token)
        final_uid, final_name, final_region = u, name, reg

    elif uid and password:
        login_method = "UID/Pass -> JWT"
        res = _get_jwt_via_uid_pass(uid, password, region_hint=region_hint)
        if "error" in res:
            return jsonify({
                "status": "error", "code": 401,
                "error": f"JWT generation failed: {res['error']}"
            }), 401
        final_jwt = res["token"]
        final_access_token = res.get("access_token")
        final_region = res.get("region")
        u, name, reg = _decode_jwt_info(final_jwt)
        final_uid = u or uid
        final_name = name
        if reg and not final_region:
            final_region = reg

    elif access:
        login_method = "Access token -> JWT"
        res = _get_jwt_via_access_token(access, region_hint=region_hint)
        if "error" in res:
            return jsonify({
                "status": "error", "code": 401,
                "error": f"JWT generation failed: {res['error']}"
            }), 401
        final_jwt = res["token"]
        final_access_token = res.get("access_token") or access
        final_region = res.get("region")
        if not res.get("opaque"):
            u, name, reg = _decode_jwt_info(final_jwt)
            final_uid = u
            final_name = name
            if reg and not final_region:
                final_region = reg

    else:
        return jsonify({
            "status": "error", "code": 400,
            "error": "Provide jwt=, or uid=+pass=, or access="
        }), 400

    if not final_jwt:
        return jsonify({"status": "error", "code": 500,
                        "error": "Could not obtain JWT"}), 500

    status_code, resp_bytes = _upload_bio(final_jwt, bio)

    if status_code == 200:
        status_text = "success"
    elif status_code == 401:
        status_text = "unauthorized"
    else:
        status_text = f"http_{status_code}"

    return jsonify({
        "status": status_text,
        "code": status_code,
        "login_method": login_method,
        "bio": bio,
        "uid": str(final_uid) if final_uid else None,
        "name": final_name,
        "region": final_region,
        "open_id": final_open_id,
        "access_token": final_access_token,
        "generated_jwt": final_jwt,
        "server_response_hex": binascii.hexlify(resp_bytes).decode("utf-8") if resp_bytes else "",
        "version": RELEASEVERSION,
    }), 200 if status_code == 200 else (400 if status_code == 401 else 500)



@app.route('/access')
def api_access():
    uid = request.args.get('uid', '').strip()
    password = request.args.get('pass', request.args.get('password', '')).strip()
    if not uid or not password:
        return jsonify({"status": "error", "message": "Missing uid or pass"}), 400
    if not uid.isdigit() or len(uid) < 8:
        return jsonify({"status": "error", "message": "Invalid UID format"}), 400
    access_token, open_id = get_user_access_token(uid, password)
    if not access_token:
        return jsonify({"status": "error", "message": "OAuth failed (check uid/password)"}), 400
    return jsonify({"status": "success", "access_token": access_token, "open_id": open_id}), 200


@app.route('/token')
def api_token():
    started = time.time()
    uid = request.args.get('uid', '').strip()
    password = request.args.get('password', request.args.get('pass', '')).strip()
    region = (request.args.get('region', 'BD').strip().upper() or 'BD')
    if not uid or not password:
        return jsonify({"status": "error", "message": "Missing uid or password"}), 400
    if not uid.isdigit() or len(uid) < 8:
        return jsonify({"status": "error", "message": "Invalid UID format"}), 400
    result, access_token, error, open_id = create_user_jwt(
        uid, password, region=region, return_open_id=True
    )
    if error or not result:
        return jsonify({"status": "error", "message": error or "JWT generation failed"}), 400
    jwt_payload = _jwt_decode_token(result.token)
    real_uid = str(jwt_payload.get("account_id", result.account_id or "N/A"))
    return jsonify({
        "status": "success",
        "real_uid": real_uid,
        "access_token": access_token,
        "open_id": open_id,
        "token": result.token,
        "time": f"{time.time() - started:.2f}s"
    }), 200



async def _try_regions(uid, force_region=None):
    if force_region and force_region.upper() in SUPPORTED_REGIONS:
        r = force_region.upper()
        try:
            data = await GetAccountInformation(uid, "7", r, "/GetPlayerPersonalShow")
            basic = data.get('basicInfo', {}) or {}
            if basic.get('accountId'):
                uid_region_cache[uid] = (basic.get('region') or r).upper()
                return r, data
        except Exception:
            pass

    last_err = None
    for r in REGION_PRIORITY:
        if r not in SUPPORTED_REGIONS:
            continue
        try:
            tok, _, _ = await get_token_info(r)
            if not tok:
                continue
            data = await GetAccountInformation(uid, "7", r, "/GetPlayerPersonalShow")
            basic = data.get('basicInfo', {}) or {}
            if basic.get('accountId'):
                uid_region_cache[uid] = (basic.get('region') or r).upper()
                return r, data
        except Exception as e:
            last_err = str(e)
            continue
    raise Exception(f"UID not found in ME/IND/BR. last_error={last_err}")



@app.route('/info')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    force = request.args.get('region')
    try:
        region, return_data = asyncio.run(_try_regions(uid, force))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    try:
        return_data = add_rank_info(return_data)
        return_data = add_equipped_items(return_data)

        if 'diamondCostRes' in return_data:
            del return_data['diamondCostRes']

        basic = return_data.get('basicInfo', {}) or {}
        if basic.get('createAt'):
            basic['createAt_bst'] = format_timestamp_bst(basic.get('createAt', '0'))
        if basic.get('lastLoginAt'):
            basic['lastLoginAt_bst'] = format_timestamp_bst(basic.get('lastLoginAt', '0'))

        return json.dumps(return_data, indent=2, ensure_ascii=False), 200, \
               {'Content-Type': 'application/json; charset=utf-8'}
    except Exception as e:
        return jsonify({"error": f"Failed to format info: {e}", "region": region}), 500



@app.route('/level')
@cached_endpoint(ttl=300)
def get_level_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        region, data = asyncio.run(_try_regions(uid, request.args.get('region')))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    try:
        basic = data.get('basicInfo', {}) or {}
        level = basic.get('level', 0)
        exp = basic.get('exp', 0)
        TOTAL_EXP_TO_LEVEL_100 = 32032278
        remaining_exp = max(0, TOTAL_EXP_TO_LEVEL_100 - exp)

        exp_to_next = 0
        exp_needed_for_next_level = 0
        if level < 100:
            level_exp = [
                100, 300, 600, 1000, 1500, 2100, 2800, 3600, 4500, 5500,
                6600, 7800, 9100, 10500, 12000, 13600, 15300, 17100, 19000, 21000,
                23100, 25300, 27600, 30000, 32500, 35100, 37800, 40600, 43500, 46500,
                49600, 52800, 56100, 59500, 63000, 66600, 70300, 74100, 78000, 82000,
                86100, 90300, 94600, 99000, 103500, 108100, 112800, 117600, 122500, 127500,
                132600, 137800, 143100, 148500, 154000, 159600, 165300, 171100, 177000, 183000,
                189100, 195300, 201600, 208000, 214500, 221100, 227800, 234600, 241500, 248500,
                255600, 262800, 270100, 277500, 285000, 292600, 300300, 308100, 316000, 324000,
                332100, 340300, 348600, 357000, 365500, 374100, 382800, 391600, 400500, 409500,
                418600, 427800, 437100, 446500, 456000, 465600, 475300, 485100, 495000, 505000
            ]
            if 1 <= level <= len(level_exp):
                exp_needed_for_next_level = level_exp[level - 1]
                exp_to_next = max(0, exp_needed_for_next_level - exp)

        return jsonify({
            "uid": uid,
            "username": basic.get('nickname', 'Unknown'),
            "region": basic.get('region', region),
            "level": level,
            "exp": exp,
            "likes": basic.get('liked', 0),
            "badge_count": basic.get('badgeCnt', 0),
            "exp_to_next_level": exp_to_next,
            "exp_needed_for_next_level": exp_needed_for_next_level,
            "total_exp_needed_for_level_100": remaining_exp
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch level info: {e}"}), 500


@app.route('/region')
@cached_endpoint(ttl=300)
def get_region_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        region, data = asyncio.run(_try_regions(uid, request.args.get('region')))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    try:
        basic = data.get('basicInfo', {}) or {}
        return jsonify({
            "uid": uid,
            "username": basic.get('nickname', 'Unknown'),
            "region": basic.get('region', region),
            "level": basic.get('level', 0),
            "likes": basic.get('liked', 0),
            "created_at": format_timestamp_bst(basic.get('createAt', '0')),
            "last_login": format_timestamp_bst(basic.get('lastLoginAt', '0')),
            "has_elite_pass": basic.get('hasElitePass', False),
            "account_type": basic.get('accountType', 0),
            "season_id": basic.get('seasonId', 0),
            "release_version": basic.get('releaseVersion', 'Unknown')
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch region info: {e}"}), 500



@app.route('/leader')
@cached_endpoint(ttl=300)
def get_leader_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        region, user_data = asyncio.run(_try_regions(uid, request.args.get('region')))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    try:
        captain_basic = user_data.get('captainBasicInfo', {}) or {}
        clan_basic = user_data.get('clanBasicInfo', {}) or {}
        if not captain_basic or not clan_basic:
            return jsonify({"error": "User is not in a clan or no leader found."}), 404

        captain_uid = captain_basic.get('accountId')
        leader_data = asyncio.run(GetAccountInformation(
            captain_uid, "7", captain_basic.get('region') or region, "/GetPlayerPersonalShow"))
        leader_basic = leader_data.get('basicInfo', {}) or {}
        leader_profile = leader_data.get('profileInfo', {}) or {}

        return jsonify({
            "uid": captain_uid,
            "username": leader_basic.get('nickname', 'Unknown'),
            "region": leader_basic.get('region', region),
            "level": leader_basic.get('level', 0),
            "exp": leader_basic.get('exp', 0),
            "likes": leader_basic.get('liked', 0),
            "rank": leader_basic.get('rank', 0),
            "ranking_points": leader_basic.get('rankingPoints', 0),
            "rank_name": get_br_rank_with_score(leader_basic.get('rankingPoints', 0)),
            "cs_rank_name": get_cs_rank_with_score(leader_basic.get('csRankingPoints', 0)),
            "max_rank": leader_basic.get('maxRank', 0),
            "cs_rank": leader_basic.get('csRank', 0),
            "cs_ranking_points": leader_basic.get('csRankingPoints', 0),
            "badge_count": leader_basic.get('badgeCnt', 0),
            "badge_id": leader_basic.get('badgeId', 0),
            "title": leader_basic.get('title', 0),
            "banner_id": leader_basic.get('bannerId', 0),
            "head_pic": leader_basic.get('headPic', 0),
            "pin_id": leader_basic.get('pinId', 0),
            "has_elite_pass": leader_basic.get('hasElitePass', False),
            "account_type": leader_basic.get('accountType', 0),
            "season_id": leader_basic.get('seasonId', 0),
            "release_version": leader_basic.get('releaseVersion', 'Unknown'),
            "created_at": format_timestamp_bst(leader_basic.get('createAt', '0')),
            "last_login": format_timestamp_bst(leader_basic.get('lastLoginAt', 0)),
            "weapon_skins": leader_basic.get('weaponSkinShows', []),
            "equipped_items": {
                "avatar_id": leader_profile.get('avatarId', 0),
                "skin_color": leader_profile.get('skinColor', 0),
                "clothes": leader_profile.get('clothes', []),
                "equipped_skills": leader_profile.get('equipedSkills', []),
                "is_selected": leader_profile.get('isSelected', False),
                "is_selected_awaken": leader_profile.get('isSelectedAwaken', False),
                "pve_primary_weapon": leader_profile.get('pvePrimaryWeapon', 0),
                "equipped_animation_id": leader_profile.get('equippedAnimationId', 0)
            },
            "clan_name": clan_basic.get('clanName', 'Unknown'),
            "clan_id": clan_basic.get('clanId', 'Unknown'),
            "clan_level": clan_basic.get('clanLevel', 0),
            "clan_capacity": clan_basic.get('capacity', 0),
            "clan_members": clan_basic.get('memberNum', 0),
            "is_leader": True
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch leader info: {e}"}), 500


def _fetch_icon_image(item_id):
    if not item_id:
        return None
    try:
        response = requests.get(
            ICON_API_URL.format(item_id),
            timeout=IMAGE_REQUEST_TIMEOUT,
            verify=False
        )
        response.raise_for_status()
        return Image.open(BytesIO(response.content)).convert("RGBA")
    except (requests.RequestException, OSError, ValueError):
        return None


def _load_font(size, bold=False):
    candidates = (
        [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"
        ]
        if bold else
        [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"
        ]
    )
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                pass
    return ImageFont.load_default()


def _fit_image(img, size):
    img = img.copy()
    img.thumbnail((size, size), Image.LANCZOS)
    output = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    output.alpha_composite(
        img,
        ((size - img.width) // 2, (size - img.height) // 2)
    )
    return output


def _make_hex_item(img, size=154):
    pad = 15
    icon = _fit_image(img, size - pad * 2)
    tile = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    points = [
        (size * 0.5, 2),
        (size - 3, size * 0.25),
        (size - 3, size * 0.75),
        (size * 0.5, size - 3),
        (3, size * 0.75),
        (3, size * 0.25)
    ]
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon(points, fill=255)
    panel = Image.new("RGBA", (size, size), (13, 8, 34, 230))
    panel.putalpha(mask)
    tile.alpha_composite(panel)
    tile.alpha_composite(
        icon,
        ((size - icon.width) // 2, (size - icon.height) // 2)
    )
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.line(points + [points[0]], fill=(174, 83, 255, 255), width=5, joint="curve")
    tile.alpha_composite(glow.filter(ImageFilter.GaussianBlur(7)))
    tile.alpha_composite(glow)
    return tile


def _make_character_frame(img, width=470, height=630):
    frame = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    inner = img.convert("RGBA").copy()
    scale = min(
        (width - 24) / max(1, inner.width),
        (height - 24) / max(1, inner.height)
    )
    new_size = (
        max(1, int(inner.width * scale)),
        max(1, int(inner.height * scale))
    )
    inner = inner.resize(new_size, Image.LANCZOS)
    frame.alpha_composite(
        inner,
        ((width - inner.width) // 2, (height - inner.height) // 2)
    )
    return frame


def _fetch_character_image(data, avatar_id):
    profile = data.get("profileInfo") or {}
    basic = data.get("basicInfo") or {}
    candidates = (
        profile.get("characterImage"),
        profile.get("character_image"),
        profile.get("outfitImage"),
        profile.get("outfit_image"),
        profile.get("modelImage"),
        profile.get("model_image"),
        basic.get("characterImage"),
        basic.get("character_image")
    )
    for candidate in candidates:
        if isinstance(candidate, str):
            if candidate.startswith(("http://", "https://")):
                try:
                    response = requests.get(candidate, timeout=IMAGE_REQUEST_TIMEOUT, verify=False)
                    response.raise_for_status()
                    return Image.open(BytesIO(response.content)).convert("RGBA")
                except (requests.RequestException, OSError, ValueError):
                    continue
            image = _fetch_icon_image(candidate)
            if image:
                return image
    return _fetch_icon_image(avatar_id)


def _add_neon_stage(canvas):
    width, height = canvas.size
    glow = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse(
        (width * 0.28, height * 0.08, width * 0.72, height * 0.82),
        fill=(92, 28, 190, 38)
    )
    canvas.alpha_composite(glow.filter(ImageFilter.GaussianBlur(110)))


def _draw_centered_text(draw, text, y, font, fill, canvas_width, stroke_width=0):
    box = draw.textbbox((0, 0), text, font=font, stroke_width=stroke_width)
    text_width = box[2] - box[0]
    x = (canvas_width - text_width) // 2
    draw.text(
        (x, y),
        text,
        font=font,
        fill=fill,
        stroke_width=stroke_width,
        stroke_fill=(0, 0, 0, 220)
    )


def _render_outfit_image(data, uid):
    basic = data.get("basicInfo") or {}
    profile = data.get("profileInfo") or {}
    pet = data.get("petInfo") or {}

    equipped_profile = profile.get("equipped_items") or {}
    equipped_basic = basic.get("equipped_items") or {}

    clothes = profile.get("clothes") or equipped_profile.get("clothes", [])
    weapon_skins = basic.get("weaponSkinShows") or equipped_basic.get("weapon_skins", [])
    pet_skin_id = pet.get("skinId")
    avatar_id = profile.get("avatarId") or equipped_profile.get("avatar_id")

    bg_path = os.path.join(os.path.dirname(__file__), BACKGROUND_FILENAME)
    if not os.path.exists(bg_path):
        raise FileNotFoundError("Background image not found")

    bg = Image.open(bg_path).convert("RGBA")
    canvas = bg.copy()
    width, height = canvas.size

    _add_neon_stage(canvas)

    item_ids = (
        list(clothes[:6])
        + list(weapon_skins[:3])
        + ([pet_skin_id] if pet_skin_id else [])
    )
    item_ids = (item_ids + [None] * 10)[:10]

    if item_ids[0] and item_ids[4]:
        item_ids[0], item_ids[4] = item_ids[4], item_ids[0]

    tile_size = 154
    y_positions = [70, 260, 450, 640, 830]
    left_x = 54
    right_x = width - left_x - tile_size
    positions = (
        [(left_x, y) for y in y_positions]
        + [(right_x, y) for y in y_positions]
    )

    for item_id, (x, y) in zip(item_ids, positions):
        if not item_id:
            continue
        icon_img = _fetch_icon_image(item_id)
        if icon_img:
            tile = _make_hex_item(icon_img, tile_size)
            canvas.alpha_composite(tile, (x, y))

    character = _fetch_character_image(data, avatar_id)
    if character:
        frame = _make_character_frame(character, width=470, height=630)
        cx = (width - frame.width) // 2
        cy = 180
        canvas.alpha_composite(frame, (cx, cy))

    nickname = str(basic.get("nickname") or uid)
    draw = ImageDraw.Draw(canvas)
    name_font = _load_font(30, bold=True)
    while (
        draw.textbbox((0, 0), nickname, font=name_font)[2] > width - 100
        and getattr(name_font, "size", 30) > 16
    ):
        name_font = _load_font(getattr(name_font, "size", 30) - 2, bold=True)

    name_y = min(height - 76, 1050)
    _draw_centered_text(draw, nickname, name_y, name_font, (255, 225, 145, 255), width, 1)

    output = BytesIO()
    canvas.save(output, format="PNG", optimize=True)
    output.seek(0)
    return output.getvalue()


def render_wishlist_grid(nickname, item_ids):
    tile_size = 110
    pad = 18
    header_h = 90
    cols = 6

    valid_items = []
    for iid in item_ids:
        icon = _fetch_icon_image(iid)
        if icon:
            valid_items.append(icon)

    rows = max(1, (len(valid_items) + cols - 1) // cols)
    width = cols * tile_size + (cols + 1) * pad
    height = header_h + rows * tile_size + (rows + 1) * pad

    canvas = Image.new("RGBA", (width, height), (10, 6, 24, 255))
    _add_neon_stage(canvas)

    draw = ImageDraw.Draw(canvas)
    title_font = _load_font(30, bold=True)
    sub_font = _load_font(18, bold=False)

    _draw_centered_text(draw, nickname, 20, title_font, (255, 225, 145, 255), width, 1)
    _draw_centered_text(
        draw,
        f"Wishlist Items: {len(valid_items)}",
        58,
        sub_font,
        (180, 220, 255, 255),
        width
    )

    for idx, icon in enumerate(valid_items):
        r = idx // cols
        c = idx % cols
        x = pad + c * (tile_size + pad)
        y = header_h + pad + r * (tile_size + pad)
        tile = _make_hex_item(icon, tile_size)
        canvas.alpha_composite(tile, (x, y))

    output = BytesIO()
    canvas.save(output, format="PNG", optimize=True)
    output.seek(0)
    return output.getvalue()


@app.route('/item', methods=['GET'])
def get_item_image():
    item_id = (request.args.get('id') or request.args.get('item-id') or '').strip()
    if not item_id:
        return jsonify({"error": "Please provide item ID. Example: /item?id=909000010"}), 400

    item_image = _fetch_icon_image(item_id)
    if item_image is None:
        return jsonify({"error": f"Item image not found for UID: {item_id}"}), 404

    output = BytesIO()
    item_image.save(output, format="PNG", optimize=True)
    output.seek(0)
    return Response(output.getvalue(), mimetype="image/png",
                    headers={"Cache-Control": "public, max-age=3600"})


@app.route('/wishlist')
def get_wishlist():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        region, info_data = asyncio.run(_try_regions(uid, request.args.get('region')))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

    basic = info_data.get('basicInfo', {}) or {}
    real_region = (basic.get('region') or region or "IND").upper()
    nickname = str(basic.get('nickname') or uid)

    item_ids = []
    try:
        data = asyncio.run(GetWishList(uid, real_region))
        for it in data.get('items', []):
            iid = it.get('itemId') or it.get('item_id')
            if iid:
                item_ids.append(iid)
    except Exception as e:
        return jsonify({"error": f"Wishlist fetch failed: {e}"}), 500

    if not item_ids:
        return jsonify({
            "uid": uid,
            "username": nickname,
            "region": real_region,
            "total_items": 0,
            "note": "No wishlist items found"
        }), 200

    try:
        img_bytes = render_wishlist_grid(nickname, item_ids)
        return Response(img_bytes, mimetype="image/png")
    except Exception:
        app.logger.exception("Wishlist image generation failed")
        return jsonify({"error": "Image generation failed"}), 500


@app.route("/shappno-outfit", methods=["GET"])
def shappno_outfit():
    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"error": "Missing uid"}), 400

    try:
        region, data = asyncio.run(_try_regions(uid, request.args.get("region")))
    except Exception as e:
        return jsonify({"error": f"Player info unavailable: {e}"}), 502

    try:
        data = add_equipped_items(data)
    except Exception:
        pass

    try:
        png_bytes = _render_outfit_image(data, uid)
        return Response(png_bytes, mimetype="image/png")
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500
    except Exception:
        app.logger.exception("Outfit image generation failed")
        return jsonify({"error": "Image generation failed"}), 500


def decode_author_uid(token):
    try:
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except Exception:
        return None


def get_server_from_token(token):
    try:
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        lock_region = decoded.get("lock_region", "IND")
        return lock_region.upper()
    except Exception:
        return "IND"


def get_base_url(server_name):
    server_name = (server_name or "").upper()
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ppmainecoonghj.com/"


def create_info_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()


def get_player_info(target_uid, token, server_name=None):
    try:
        if not server_name:
            server_name = get_server_from_token(token)

        protobuf_data = create_info_protobuf(target_uid)
        encrypted_data = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, protobuf_data).hex()
        endpoint = get_base_url(server_name) + "GetPlayerPersonalShow"

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        response = requests.post(endpoint, data=bytes.fromhex(encrypted_data),
                                 headers=headers, verify=False, timeout=10)

        if response.status_code != 200:
            return None

        info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        info.ParseFromString(response.content)
        return info
    except Exception as e:
        print(f"[PlayerInfo] Error: {e}")
        return None


def extract_player_info(info_data):
    if not info_data:
        return None
    try:
        basic_info = info_data.basic_info
        return {
            'uid': basic_info.account_id,
            'nickname': basic_info.nickname,
            'level': basic_info.level,
            'region': basic_info.region,
            'likes': basic_info.liked,
            'release_version': basic_info.release_version
        }
    except Exception:
        return None


def retry_operation(default_max_retries=10, default_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            max_retries = kwargs.pop("max_retries", default_max_retries)
            delay = kwargs.pop("delay", default_delay)
            last_exception = None
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    if result and result.get('status') == 'success':
                        return result
                    print(f"[Retry] Attempt {attempt + 1}/{max_retries} → "
                          f"status={result.get('status') if result else None}")
                except Exception as e:
                    last_exception = e
                    print(f"[Retry] Attempt {attempt + 1}/{max_retries} failed: {str(e)}")

                if attempt < max_retries - 1:
                    time.sleep(delay)

            if last_exception:
                return {
                    "status": "error",
                    "message": f"All {max_retries} attempts failed",
                    "error": str(last_exception)
                }
            return {
                "status": "error",
                "message": f"All {max_retries} attempts failed"
            }
        return wrapper
    return decorator


@retry_operation()
def remove_friend_with_retry(author_uid, target_uid, token, server_name=None):
    try:
        if not server_name:
            server_name = get_server_from_token(token)

        player_info = get_player_info(target_uid, token, server_name)

        msg = RemoveFriend_Req_pb2.RemoveFriend()
        msg.AuthorUid = int(author_uid)
        msg.TargetUid = int(target_uid)
        encrypted_bytes = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, msg.SerializeToString())

        url = get_base_url(server_name) + "RemoveFriend"
        headers = {
            'Authorization': f"Bearer {token}",
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9)",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        res = requests.post(url, data=encrypted_bytes, headers=headers,
                            verify=False, timeout=10)

        player_data = extract_player_info(player_info)

        if res.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {res.status_code}: {res.text[:200]}")

        return {
            "author_uid": author_uid,
            "nickname": player_data.get('nickname') if player_data else "Unknown",
            "uid": target_uid,
            "level": player_data.get('level') if player_data else 0,
            "likes": player_data.get('likes') if player_data else 0,
            "region": player_data.get('region') if player_data else "Unknown",
            "release_version": player_data.get('release_version') if player_data else "Unknown",
            "status": status,
            "time": dt.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        print(f"[RemoveFriend] Error: {e}")
        raise e


@retry_operation()
def send_friend_request_with_retry(author_uid, target_uid, token, server_name=None):
    try:
        if not server_name:
            server_name = get_server_from_token(token)

        player_info = get_player_info(target_uid, token, server_name)

        encrypted_id = Encrypt_ID(target_uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = get_base_url(server_name) + "RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9)"
        }

        r = requests.post(url, headers=headers,
                          data=bytes.fromhex(encrypted_payload),
                          verify=False, timeout=10)

        player_data = extract_player_info(player_info)

        if r.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {r.status_code}: {r.text[:200]}")

        return {
            "author_uid": author_uid,
            "nickname": player_data.get('nickname') if player_data else "Unknown",
            "uid": target_uid,
            "level": player_data.get('level') if player_data else 0,
            "likes": player_data.get('likes') if player_data else 0,
            "region": player_data.get('region') if player_data else "Unknown",
            "release_version": player_data.get('release_version') if player_data else "Unknown",
            "status": status,
            "time": dt.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        print(f"[AddFriend] Error: {e}")
        raise e


@app.route('/add_friend', methods=['GET'])
def adding_friend_custom():
    uid = request.args.get('uid')
    password = request.args.get('password')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name')  # optional

    if not uid or not password or not friend_uid:
        return jsonify({"status": "failed",
                        "message": "Missing uid, password, or friend_uid"}), 400

    if server_name:
        result, access_token, error = create_user_jwt(uid, password, region=server_name)
    else:
        result = None
        error = None
        for try_region in ["BD", "ME", "IND", "BR"]:
            result, access_token, error = create_user_jwt(uid, password, region=try_region)
            if result and result.token:
                break
            result = None

    if error or not result or not result.token:
        return jsonify({"status": "failed",
                        "message": f"JWT generation failed: {error or 'unknown'}"}), 400

    token = result.token
    author_uid = decode_author_uid(token) or str(result.account_id)
    if not author_uid:
        return jsonify({"status": "failed",
                        "message": "Invalid JWT token"}), 400

    actual_region = (result.lock_region or server_name or "IND").upper()
    response = send_friend_request_with_retry(author_uid, friend_uid, token, actual_region)
    return jsonify(response)


@app.route('/rv_friend', methods=['GET'])
def removing_friend_custom():
    uid = request.args.get('uid')
    password = request.args.get('password')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name')  # optional

    if not uid or not password or not friend_uid:
        return jsonify({"status": "failed",
                        "message": "Missing uid, password, or friend_uid"}), 400

    if server_name:
        result, access_token, error = create_user_jwt(uid, password, region=server_name)
    else:
        result = None
        error = None
        for try_region in ["BD", "ME", "IND", "BR"]:
            result, access_token, error = create_user_jwt(uid, password, region=try_region)
            if result and result.token:
                break
            result = None

    if error or not result or not result.token:
        return jsonify({"status": "failed",
                        "message": f"JWT generation failed: {error or 'unknown'}"}), 400

    token = result.token
    author_uid = decode_author_uid(token) or str(result.account_id)
    if not author_uid:
        return jsonify({"status": "failed",
                        "message": "Invalid JWT token"}), 400

    actual_region = (result.lock_region or server_name or "IND").upper()
    response = remove_friend_with_retry(author_uid, friend_uid, token, actual_region)
    return jsonify(response)








SHAPPNO_REGION_CONFIG = {
    'bd':  {'domain': 'clientbp.ppmainecoonghj.com', 'file': 'shappno_bd.txt'},
    'ind': {'domain': 'client.ind.freefiremobile.com', 'file': 'shappno_ind.txt'},
}


def _shappno_load_accounts(region_key):
    try:
        config = SHAPPNO_REGION_CONFIG.get(region_key)
        if not config:
            app.logger.error(f"[shappno-send] Unknown region: {region_key}")
            return None
        token_file = config['file']
        if not os.path.exists(token_file):
            app.logger.error(f"[shappno-send] File not found: {token_file}")
            return None
        accounts = []
        with open(token_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    uid, pwd = line.split(':', 1)
                    if uid.strip() and pwd.strip():
                        accounts.append({"uid": uid.strip(), "password": pwd.strip()})
        app.logger.info(f"[shappno-send] [{region_key}] Loaded {len(accounts)} from {token_file}")
        return accounts
    except Exception as e:
        app.logger.error(f"[shappno-send] Load error: {e}")
        return None


def _shappno_get_internal_info(target_uid):
    try:
        region, data = asyncio.run(_try_regions(target_uid))
        basic = (data or {}).get('basicInfo', {}) or {}
        name = basic.get('nickname') or "N/A"
        level = basic.get('level', "N/A")
        return name, level
    except Exception as e:
        app.logger.warning(f"[shappno-send] internal info failed: {e}")
        return "N/A", "N/A"


def _shappno_one_account(acc, target_uid, region_key, server_name):
    uid = acc['uid']
    pwd = acc['password']
    try:
        result, _access, error = create_user_jwt(uid, pwd, region=region_key.upper())
        if error or not result or not result.token:
            return {"uid": uid, "status": "jwt_failed",
                    "error": error or "no token"}

        token = result.token
        author_uid = decode_author_uid(token) or str(result.account_id)
        if not author_uid:
            return {"uid": uid, "status": "jwt_failed",
                    "error": "invalid jwt"}

        actual_region = (result.lock_region or server_name or "IND").upper()

        resp = send_friend_request_with_retry(
            author_uid, target_uid, token, actual_region,
            max_retries=2, delay=1
        )

        return {
            "uid": uid,
            "author_uid": author_uid,
            "nickname": resp.get("nickname"),
            "region": actual_region,
            "status": resp.get("status", "failed"),
            "message": resp.get("message"),
        }
    except Exception as e:
        return {"uid": uid, "status": "exception", "error": str(e)}


@app.route("/shappno-send", methods=["GET"])
def shappno_send_endpoint():
    target_uid = request.args.get("uid")
    region_key = (request.args.get("region") or "bd").lower()

    if not target_uid:
        return jsonify({"error": "uid parameter required"}), 400
    if region_key not in SHAPPNO_REGION_CONFIG:
        return jsonify({
            "error": f"Invalid region. Supported: {list(SHAPPNO_REGION_CONFIG.keys())}"
        }), 400

    player_name, player_level = _shappno_get_internal_info(target_uid)

    accounts = _shappno_load_accounts(region_key)
    if not accounts:
        return jsonify({
            "PlayerName": player_name,
            "PlayerLevel": player_level,
            "UID": target_uid,
            "Region": region_key.upper(),
            "Success": 0,
            "Failed": 0,
            "Status": 2,
            "Message": f"No accounts found in {SHAPPNO_REGION_CONFIG[region_key]['file']}",
        }), 404

    server_name = SHAPPNO_REGION_CONFIG[region_key]['domain']
    app.logger.info(
        f"[shappno-send] region={region_key} accounts={len(accounts)} "
        f"(using /add_friend system, max_retries=2)"
    )

    results = {"success": 0, "failed": 0}
    lock = threading.Lock()

    def _worker(acc):
        r = _shappno_one_account(acc, target_uid, region_key, server_name)
        with lock:
            if r.get("status") == "success":
                results["success"] += 1
            else:
                results["failed"] += 1

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(_worker, acc) for acc in accounts]
        for f in as_completed(futures):
            try:
                f.result(timeout=30)
            except Exception:
                pass

    app.logger.info(
        f"[shappno-send] [{region_key}] done: success={results['success']} "
        f"failed={results['failed']}"
    )

    return jsonify({
        "PlayerName": player_name,
        "PlayerLevel": player_level,
        "UID": target_uid,
        "Region": region_key.upper(),
        "Total": len(accounts),
        "Success": results["success"],
        "Failed": results["failed"],
        "Status": 1 if results["success"] > 0 else 2,
    }), 200


AVATAR_ZOOM = 1.26
AVATAR_SHIFT_Y = 0
AVATAR_SHIFT_X = 0
BANNER_START_X = 0.25
BANNER_START_Y = 0.29
BANNER_END_X = 0.81
BANNER_END_Y = 0.65

BASE64_ICON = "aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL1NoYWhHQ3JlYXRvci9pY29uQG1haW4vUE5H"
BANNER_ICON_URL = base64.b64decode(BASE64_ICON).decode("utf-8")

FONT_BOLD_PATH = os.path.join(os.path.dirname(__file__), "arial_unicode_bold.otf")
FONT_REGULAR_PATH = os.path.join(os.path.dirname(__file__), "NotoSansCherokee.ttf")

def _banner_load_font(size: int, bold: bool = False):
    path = FONT_BOLD_PATH if bold else FONT_REGULAR_PATH
    try:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    except Exception:
        pass
    try:
        other = FONT_REGULAR_PATH if bold else FONT_BOLD_PATH
        if os.path.exists(other):
            return ImageFont.truetype(other, size)
    except Exception:
        pass
    return ImageFont.load_default()

def _banner_fetch_image_bytes(item_id):
    if not item_id or str(item_id) == "0":
        return None
    url = ICON_API_URL.format(item_id)
    try:
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code == 200 and resp.content:
            return resp.content
    except Exception:
        pass
    return None

def _banner_bytes_to_image(img_bytes):
    if img_bytes:
        return Image.open(BytesIO(img_bytes)).convert("RGBA")
    return Image.new("RGBA", (100, 100), (0, 0, 0, 0))

def _process_banner_image(data, avatar_bytes, banner_bytes, pin_bytes):
    avatar_img = _banner_bytes_to_image(avatar_bytes)
    banner_img = _banner_bytes_to_image(banner_bytes)
    pin_img = _banner_bytes_to_image(pin_bytes)

    level = str(data.get("AccountLevel", "0"))
    name = str(data.get("AccountName", "Unknown"))
    guild = str(data.get("GuildName", ""))

    TARGET_HEIGHT = 400

    zoom_size = int(TARGET_HEIGHT * AVATAR_ZOOM)
    avatar_img = avatar_img.resize((zoom_size, zoom_size), Image.LANCZOS)

    center_x = zoom_size // 2
    center_y = zoom_size // 2
    half_target = TARGET_HEIGHT // 2

    left = center_x - half_target - AVATAR_SHIFT_X
    top = center_y - half_target - AVATAR_SHIFT_Y
    right = left + TARGET_HEIGHT
    bottom = top + TARGET_HEIGHT

    avatar_img = avatar_img.crop((left, top, right, bottom))
    av_w, av_h = avatar_img.size

    b_w, b_h = banner_img.size
    if b_w > 50 and b_h > 50:
        banner_img = banner_img.rotate(3, expand=True)
        b_w, b_h = banner_img.size

        crop_left = b_w * BANNER_START_X
        crop_top = b_h * BANNER_START_Y
        crop_right = b_w * BANNER_END_X
        crop_bottom = b_h * BANNER_END_Y
        banner_img = banner_img.crop((crop_left, crop_top, crop_right, crop_bottom))

    b_w, b_h = banner_img.size
    new_banner_w = int(TARGET_HEIGHT * (b_w / b_h) * 2) if b_h else 800
    banner_img = banner_img.resize((new_banner_w, TARGET_HEIGHT), Image.LANCZOS)

    final_w = av_w + new_banner_w
    combined = Image.new("RGBA", (final_w, TARGET_HEIGHT))

    combined.paste(avatar_img, (0, 0))
    combined.paste(banner_img, (av_w, 0))

    draw = ImageDraw.Draw(combined)

    font_large = _banner_load_font(125, bold=True)
    font_small = _banner_load_font(95, bold=True)
    font_level = _banner_load_font(50, bold=True)

    def safe_text(draw_obj, x, y, text, font, stroke=3):
        for dx in range(-stroke, stroke + 1):
            for dy in range(-stroke, stroke + 1):
                draw_obj.text((x + dx, y + dy), text, font=font, fill="black")
        draw_obj.text((x, y), text, font=font, fill="white")

    safe_text(draw, av_w + 65, 40, name, font_large, stroke=4)
    safe_text(draw, av_w + 65, 220, guild, font_small, stroke=3)

    if pin_img.size != (100, 100):
        pin_img = pin_img.resize((130, 130), Image.LANCZOS)
        combined.paste(pin_img, (0, TARGET_HEIGHT - 130), pin_img)

    lvl_text = f"Lvl.{level}"
    bbox = draw.textbbox((0, 0), lvl_text, font=font_level)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]

    draw.rectangle([final_w - w - 60, TARGET_HEIGHT - h - 50, final_w, TARGET_HEIGHT], fill="black")
    draw.text((final_w - w - 30, TARGET_HEIGHT - h - 40), lvl_text, font=font_level, fill="white")

    img_io = BytesIO()
    combined.save(img_io, "PNG")
    img_io.seek(0)
    return img_io


@app.route("/shappno-banner", methods=["GET"])
def shappno_banner_endpoint():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID required"}), 400

    try:
        region, data = asyncio.run(_try_regions(uid))
    except Exception as e:
        return jsonify({"error": f"Account not found: {e}"}), 404

    basic = data.get("basicInfo", {})
    clan = data.get("clanBasicInfo", {})

    name = basic.get("nickname", "Unknown")
    level = basic.get("level", "0")
    guild_name = clan.get("clanName", "")

    avatar_id = basic.get("headPic", 0)
    banner_id = basic.get("bannerId", 0)
    pin_id = basic.get("pinId", 0)

    avatar_bytes = _banner_fetch_image_bytes(avatar_id)
    banner_bytes = _banner_fetch_image_bytes(banner_id)
    pin_bytes = _banner_fetch_image_bytes(pin_id)

    banner_data = {
        "AccountLevel": level,
        "AccountName": name,
        "GuildName": guild_name,
    }

    try:
        img_io = _process_banner_image(banner_data, avatar_bytes, banner_bytes, pin_bytes)
        return Response(img_io.getvalue(), mimetype="image/png", headers={"Cache-Control": "public, max-age=300"})
    except Exception as e:
        app.logger.error(f"[shappno-banner] Image gen error: {e}")
        return jsonify({"error": "Image generation failed"}), 500

@app.before_request
def _ensure_tokens_ready():
    return


from google.protobuf import descriptor as _d2
from google.protobuf import descriptor_pool as _dp2
from google.protobuf import symbol_database as _sdb2
from google.protobuf.internal import builder as _bld2

_DUO_DESCRIPTOR = _dp2.Default().AddSerializedFile(
    b'\n\x1aSpidey_SpecialFriend.proto"\x87\x01\n\x0e\x44ynamicDuoData'
    b'\x12\x13\n\x0bpartner_uid\x18\x01 \x01(\x03\x12\r\n\x05score\x18\x03'
    b' \x01(\x05\x12\x1a\n\x12\x63reation_timestamp\x18\x04 \x01(\x03'
    b'\x12\x13\n\x0b\x64\x61ys_active\x18\x05 \x01(\x05\x12\x0e\n\x06status'
    b'\x18\x06 \x01(\x05J\x04\x08\x02\x10\x03J\x04\x08\x08\x10\tJ\x04\x08\t'
    b'\x10\n":\n\x15SpecialFriendResponse\x12!\n\x08\x64uo_info\x18\x01'
    b' \x01(\x0b\x32\x0f.DynamicDuoDatab\x06proto3'
)
_duo_globals = globals()
_bld2.BuildMessageAndEnumDescriptors(_DUO_DESCRIPTOR, _duo_globals)
_bld2.BuildTopDescriptorsAndMessages(
    _DUO_DESCRIPTOR, 'SpecialFriend_pb2', _duo_globals
)
SpecialFriendResponse = _duo_globals['SpecialFriendResponse']


def _duo_build_uid_protobuf(uid):
    def to_varint(n):
        res = bytearray()
        while n >= 0x80:
            res.append((n & 0x7f) | 0x80)
            n >>= 7
        res.append(n)
        return bytes(res)
    return aes_cbc_encrypt(MAIN_KEY, MAIN_IV, b"\x08" + to_varint(int(uid)))


def _duo_decrypt_response(data):
    try:
        aes = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
        dec = aes.decrypt(data)
        pad_len = dec[-1]
        if 1 <= pad_len <= 16 and all(b == pad_len for b in dec[-pad_len:]):
            dec = dec[:-pad_len]
        return dec
    except Exception:
        return data


def _duo_decode_protobuf(binary_data):
    try:
        if not binary_data or len(binary_data) < 2:
            return None, "Empty Response"
        resp = SpecialFriendResponse()
        resp.ParseFromString(binary_data)
        if not resp.HasField("duo_info"):
            return None, "No Dynamic Duo info found"
        duo = resp.duo_info
        score = duo.score
        if score < 101:    level = 1
        elif score < 301:  level = 2
        elif score < 501:  level = 3
        elif score < 801:  level = 4
        elif score < 1201: level = 5
        else:              level = 6
        status = "Active" if getattr(duo, "status", 0) == 2 else "Inactive"
        return {
            "partner_uid": str(duo.partner_uid),
            "level": level,
            "score": score,
            "days_active": duo.days_active,
            "time_created": format_timestamp_bst(duo.creation_timestamp),
            "creation_timestamp": duo.creation_timestamp,
            "status": status,
        }, None
    except Exception as e:
        return None, f"Parsing Error: {e}"


def _duo_try_region(target_uid, region, display_region=None):
    token, lock, major_server = asyncio.run(get_token_info(region))
    if not token:
        return None, f"Token unavailable for {region}"

    headers = {
        "Authorization": token,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USERAGENT,
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
        "Connection": "Keep-Alive",
    }
    payload = _duo_build_uid_protobuf(target_uid)

    candidates = _candidate_servers(region, major_server)
    last_err = None
    for base in candidates:
        url = base.rstrip("/") + "/GetSpecialFriendList"
        try:
            resp = requests.post(url, headers=headers, data=payload,
                                 timeout=15, verify=False)
        except Exception as e:
            last_err = f"{base}: {e}"
            continue
        if resp.status_code == 200 and resp.content:
            dec = _duo_decrypt_response(resp.content)
            return _duo_decode_protobuf(dec)
        last_err = f"{base}: HTTP {resp.status_code}"
    return None, f"All servers failed: {last_err}"


def _duo_resolve_and_fetch(target_uid):
    try:
        data, err = _duo_try_region(target_uid, "ME", display_region="BD")
        if not err and data:
            return data, None, "BD"
    except Exception as e:
        app.logger.warning(f"[duo] ME attempt failed: {e}")

    try:
        cached_tokens.pop("IND", None)  # force fresh IND token
        data, err = _duo_try_region(target_uid, "IND", display_region="IND")
        if not err and data:
            return data, None, "IND"
        return None, err or "IND failed", None
    except Exception as e:
        return None, str(e), None


@app.route("/duo-ck", methods=["GET"])
@cached_endpoint(ttl=120)
def duo_ck_endpoint():
    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"status": "error", "message": "Missing 'uid' parameter"}), 400
    if not uid.isdigit():
        return jsonify({"status": "error", "message": "UID must contain only numbers"}), 400

    try:
        data, err, region_used = _duo_resolve_and_fetch(uid)
    except Exception as e:
        app.logger.exception("[duo] fetch failed")
        return jsonify({"status": "error", "uid": uid,
                        "message": f"Server error: {e}"}), 500

    if err or not data:
        return jsonify({"status": "error", "uid": uid,
                        "message": err or "Not found"}), 404

    return jsonify({
        "status": "success",
        "uid": uid,
        "region": region_used,
        "data": data,
    })


CLAN_REGION_SERVER_MAP = {
    "IND":     "https://client.ind.freefiremobile.com",
    "ME":      "https://clientbp.ppmainecoonghj.com",
    "BD":      "https://clientbp.ppmainecoonghj.com",
    "PK":      "https://clientbp.ppmainecoonghj.com",
    "SG":      "https://clientbp.ppmainecoonghj.com",
    "ID":      "https://clientbp.ppmainecoonghj.com",
    "RU":      "https://clientbp.ppmainecoonghj.com",
    "TH":      "https://clientbp.ppmainecoonghj.com",
    "VN":      "https://clientbp.ppmainecoonghj.com",
    "CIS":     "https://clientbp.ppmainecoonghj.com",
    "BR":      "https://client.us.freefiremobile.com",
    "US":      "https://client.us.freefiremobile.com",
    "NA":      "https://client.us.freefiremobile.com",
    "SAC":     "https://client.us.freefiremobile.com",
    "EUROPE":  "https://clientbp.ppmainecoonghj.com",
}
CLAN_DEFAULT_SERVER_URL = "https://clientbp.ppmainecoonghj.com"

CLAN_GAME_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": RELEASEVERSION,
    "Expect": "100-continue",
}


def _clan_get_server_url(region):
    r = (region or "ME").upper()
    return CLAN_REGION_SERVER_MAP.get(r, CLAN_DEFAULT_SERVER_URL)


def _clan_encrypt_payload(data):
    return aes_cbc_encrypt(MAIN_KEY, MAIN_IV, data)


def _clan_request_join(jwt_token, clan_id, region):
    server_url = _clan_get_server_url(region)
    msg = ReqCLan_pb2.MyMessage()
    msg.field_1 = int(clan_id)
    payload = _clan_encrypt_payload(msg.SerializeToString())

    headers = CLAN_GAME_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt_token}"
    url = f"{server_url}/RequestJoinClan"

    r = requests.post(url, headers=headers, data=payload,
                      verify=False, timeout=20)
    return r.status_code, r.text


def _clan_quit(jwt_token, clan_id, region):
    server_url = _clan_get_server_url(region)
    msg = QuitClanReq_pb2.QuitClanReq()
    msg.field_1 = int(clan_id)
    payload = _clan_encrypt_payload(msg.SerializeToString())

    headers = CLAN_GAME_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt_token}"
    url = f"{server_url}/QuitClan"

    r = requests.post(url, headers=headers, data=payload,
                      verify=False, timeout=20)
    return r.status_code, r.text


def _clan_resolve_login(jwt_token=None, uid=None, password=None, region_hint=None):
    if jwt_token:
        try:
            parts = jwt_token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
                acc_id = payload.get("account_id")
                nick = payload.get("nickname")
                lock = (payload.get("lock_region") or "").upper()
                if region_hint and region_hint.upper() in CLAN_REGION_SERVER_MAP:
                    disp = region_hint.upper()
                elif lock:
                    disp = lock
                else:
                    disp = "ME"
                return jwt_token, str(acc_id) if acc_id else None, nick, disp, "JWT"
        except Exception:
            pass
        return None, None, None, None, "Invalid JWT"

    if uid and password:
        try:
            if region_hint and region_hint.upper() in CLAN_REGION_SERVER_MAP:
                order = [region_hint.upper()]
            else:
                order = ["ME", "IND", "BR", "US"]

            last_err = None
            for r in order:
                result, _, error = create_user_jwt(uid, password, region=r)
                if error or not result or not result.token:
                    last_err = error or "JWT generation failed"
                    continue
                real_uid = str(result.account_id or "")
                real_region = (result.lock_region or r).upper()
                return result.token, real_uid, None, real_region, f"UID_PASS({r})"

            return None, None, None, None, f"JWT generation failed: {last_err}"
        except Exception as e:
            return None, None, None, None, f"Exception: {e}"

    return None, None, None, None, "No login credentials provided"


def _clan_do_action(action_name, action_func):
    try:
        clan_id = request.args.get("clan_id")
        jwt_token = request.args.get("jwt")
        uid = request.args.get("uid")
        password = request.args.get("pass") or request.args.get("password")
        region_hint = request.args.get("region")

        if not clan_id:
            return jsonify({"success": False, "error": "clan_id required"}), 400

        final_jwt, real_uid, name, region, method = _clan_resolve_login(
            jwt_token=jwt_token, uid=uid, password=password,
            region_hint=region_hint
        )
        if not final_jwt:
            return jsonify({"success": False, "error": method}), 400

        code, text = action_func(final_jwt, clan_id, region)

        return jsonify({
            "success": (code == 200),
            "action": action_name,
            "clan_id": clan_id,
            "uid": real_uid or uid,
            "name": name,
            "region": region,
            "login_method": method,
            "developer": "SHAPPNO",
            "telegram": "@SHAPPNO_04X",
            "api_version": RELEASEVERSION,
            "server_response": text
        }), 200 if code == 200 else 500
    except Exception as e:
        app.logger.exception(f"[clan] {action_name} failed")
        return jsonify({
            "success": False,
            "error": "internal_error",
            "detail": str(e),
            "type": type(e).__name__
        }), 500


@app.route("/request_clan", methods=["GET"])
def api_request_clan():
    return _clan_do_action("Join Clan", _clan_request_join)


@app.route("/quit_clan", methods=["GET"])
def api_quit_clan():
    return _clan_do_action("Quit Clan", _clan_quit)



NICK_REGION_URL = {
    "ME":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "BD":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "PK":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "SG":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "ID":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "RU":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "TH":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "VN":      "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "CIS":     "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "EUROPE":  "https://loginbp.ppmainecoonghj.com/MajorModifyNickname",
    "IND":     "https://client.ind.freefiremobile.com/MajorModifyNickname",
    "BR":      "https://client.us.freefiremobile.com/MajorModifyNickname",
    "US":      "https://client.us.freefiremobile.com/MajorModifyNickname",
    "NA":      "https://client.us.freefiremobile.com/MajorModifyNickname",
    "SAC":     "https://client.us.freefiremobile.com/MajorModifyNickname",
}
NICK_DEFAULT_URL = "https://loginbp.ppmainecoonghj.com/MajorModifyNickname"


def _nick_get_url(region):
    r = (region or "ME").upper()
    return NICK_REGION_URL.get(r, NICK_DEFAULT_URL)


def _nick_decode_ff_name(b64_str):
    try:
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key[i % len(key)]
            decrypted_bytes.append(byte ^ key_byte)
        return decrypted_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return None


def _nick_extract_jwt_info(jwt_token):
    try:
        payload_b64 = jwt_token.split('.')[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        account_id = decoded.get("account_id")
        enc_nick = decoded.get("nickname")
        old_name = _nick_decode_ff_name(enc_nick) if enc_nick else "Unknown"
        region = decoded.get("lock_region", "Unknown")
        release_version = decoded.get("release_version", "Unknown")
        return account_id, old_name, region, release_version
    except Exception:
        return None, "Unknown", "Unknown", "Unknown"


def _nick_execute_change(jwt_token, target_name, auth_type, region_hint=None):
    account_id, old_name, region, release_version = _nick_extract_jwt_info(jwt_token)

    url_region = (region_hint or region or "ME").upper()

    candidate_urls = []
    primary = _nick_get_url(url_region)
    if primary not in candidate_urls:
        candidate_urls.append(primary)
    if NICK_DEFAULT_URL not in candidate_urls:
        candidate_urls.append(NICK_DEFAULT_URL)

    msg = nick_data_pb2.Message()
    msg.data = target_name.encode("utf-8")
    msg.timestamp = int(time.time() * 1000)
    encrypted_data = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, msg.SerializeToString())

    request_headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

    last_response = None
    used_url = None
    for url in candidate_urls:
        try:
            resp = requests.post(url, data=encrypted_data, headers=request_headers,
                                 verify=False, timeout=15)
            last_response = resp
            used_url = url
            if resp.status_code == 200:
                break
        except Exception as e:
            app.logger.warning(f"[nick] {url} failed: {e}")
            continue

    if last_response is None:
        return jsonify({
            "metadata": {
                "author": "SHAPPNO",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "response_status": "ERROR",
            "error_message": "All nickname servers failed"
        }), 500

    success_flag = last_response.status_code == 200

    try:
        raw_text = last_response.content.decode('utf-8', errors='ignore')
        plaintext = ''.join(c for c in raw_text if ord(c) >= 32)
    except Exception:
        plaintext = last_response.text

    result = {
        "metadata": {
            "author": "SHAPPNO",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        },
        "response_status": "SUCCESS" if success_flag else "FAILED",
        "operation_message": "Nickname successfully changed!" if success_flag else "Failed to alter nickname.",
        "http_status_code": last_response.status_code,
        "used_url": used_url,
        "account_details": {
            "authentication_method": auth_type,
            "account_id": account_id,
            "old_name": old_name,
            "new_name": target_name,
            "region": url_region,
            "release_version": release_version,
        },
        "server_feedback": {
            "headers": dict(last_response.headers),
            "raw_hexadecimal": last_response.content.hex(),
            "plaintext_response": plaintext
        }
    }
    return jsonify(result), last_response.status_code


@app.route("/guest", methods=["GET"])
def api_nick_guest():
    uid = request.args.get("uid")
    pwd = request.args.get("password")
    name = request.args.get("name")
    region_hint = request.args.get("region")

    if not uid or not pwd or not name:
        return jsonify({
            "response_status": "ERROR",
            "error_message": "Missing uid, password, or name"
        }), 400

    if region_hint and region_hint.upper() in CLAN_REGION_SERVER_MAP:
        order = [region_hint.upper()]
    else:
        order = ["ME", "IND", "BR", "US"]

    last_err = None
    for r in order:
        result, _, error = create_user_jwt(uid, pwd, region=r)
        if error or not result or not result.token:
            last_err = error or "JWT generation failed"
            continue
        return _nick_execute_change(
            jwt_token=result.token,
            target_name=name,
            auth_type=f"UID_PASS({r})",
            region_hint=r
        )

    return jsonify({
        "response_status": "ERROR",
        "error_message": f"JWT generation failed: {last_err}"
    }), 401


@app.route("/jwt-to-change", methods=["GET"])
def api_nick_jwt():
    jwt_token = request.args.get("jwt")
    name = request.args.get("name")
    region_hint = request.args.get("region")

    if not jwt_token or not name:
        return jsonify({
            "response_status": "ERROR",
            "error_message": "Missing jwt or name"
        }), 400

    return _nick_execute_change(
        jwt_token=jwt_token,
        target_name=name,
        auth_type="JWT_DIRECT",
        region_hint=region_hint
    )


EMOTE_DATA_HEX = "CA F6 83 22 2A 25 C7 BE FE B5 1F 59 54 4D B3 13"
EMOTE_DATA = bytes.fromhex(EMOTE_DATA_HEX.replace(" ", ""))

EMOTE_REGION_SERVER_MAP = {
    "BD": "https://clientbp.ppmainecoonghj.com",
    "IND": "https://client.ind.freefiremobile.com",
    "PK": "https://clientbp.ppmainecoonghj.com",
    "ME": "https://clientbp.ppmainecoonghj.com",
    "VN": "https://clientbp.ppmainecoonghj.com",
    "SG": "https://clientbp.ppmainecoonghj.com",
    "ID": "https://clientbp.ppmainecoonghj.com",
    "TH": "https://clientbp.ppmainecoonghj.com",
    "BR": "https://client.us.freefiremobile.com",
    "NA": "https://client.us.freefiremobile.com",
    "US": "https://client.us.freefiremobile.com",
    "RU": "https://clientbp.ggpolarbear.com",
}

EMOTE_BASE_HEADERS = {
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "ReleaseVersion": RELEASEVERSION,
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
    "X-GA": "v1 1",
    "X-Unity-Version": "2018.4.11f1",
}


def _emote_decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception:
        return None


def _emote_get_region(payload):
    return payload.get("noti_region") or payload.get("lock_region")


def _emote_get_real_uid(payload):
    return payload.get("account_id") or payload.get("external_uid")


def _emote_send_request(jwt, base_url):
    url = f"{base_url}/ChooseEmote"
    headers = EMOTE_BASE_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt}"
    return requests.post(url, headers=headers, data=EMOTE_DATA, timeout=15, verify=False)


def _emote_perform_flow(jwt_token):
    payload = _emote_decode_jwt_payload(jwt_token)
    if not payload:
        return False, "invalid_jwt"

    region = _emote_get_region(payload)
    if not region:
        return False, "no_region"

    server_url = EMOTE_REGION_SERVER_MAP.get(region.upper())
    if not server_url:
        return False, "unsupported_region"

    try:
        resp = _emote_send_request(jwt_token, server_url)
    except requests.exceptions.RequestException:
        return False, "request_failed"

    if resp.status_code != 200:
        return False, f"http_{resp.status_code}"

    body_text = ""
    try:
        body_text = resp.content.decode('utf-8', errors='ignore')
    except Exception:
        pass

    if "BR_INVENTORY_NOT_ENOUGH_ITEMS" in body_text:
        return False, "emote_not_in_vault"

    return True, "ok"


@app.route('/emote-eq', methods=['GET'])
def api_emote_eq():
    if request.args.get('emote_enquip') is None:
        return jsonify({"result": "failed", "reason": "missing_emote_enquip"}), 400

    uid = request.args.get('uid')
    password = request.args.get('password')
    region_hint = request.args.get('region')

    if not uid or not password:
        return jsonify({"result": "failed", "reason": "missing_uid_or_password"}), 400

    if region_hint and region_hint.upper() in EMOTE_REGION_SERVER_MAP:
        order = [region_hint.upper()]
    else:
        order = ["ME", "IND", "BR", "US"]

    last_err = None
    for r in order:
        result, _, error = create_user_jwt(uid, password, region=r)
        if error or not result or not result.token:
            last_err = error or "JWT generation failed"
            continue

        payload = _emote_decode_jwt_payload(result.token)
        real_uid = _emote_get_real_uid(payload) if payload else None

        ok, reason = _emote_perform_flow(result.token)

        if ok:
            return jsonify({
                "result": "success",
                "uid": real_uid,
                "region": r,
            }), 200
        else:
            return jsonify({
                "result": "failed",
                "uid": real_uid,
                "reason": reason,
            }), 400

    return jsonify({
        "result": "failed",
        "reason": f"JWT generation failed: {last_err}",
    }), 401



GARENA_ANTIHACK_URL = "https://ff.garena.com/api/antihack/check_banned"

GARENA_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'authority': 'ff.garena.com',
    'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'referer': 'https://ff.garena.com/en/support/',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'x-requested-with': 'B6FksShzIgjfrYImLpTsadjS86sddhFH',
}

def _ban_format_duration(total_seconds):
    total_seconds = max(0, int(total_seconds))
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    parts = []
    if days > 0:
        parts.append(f"{days} Day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} Hour{'s' if hours != 1 else ''}")
    if minutes > 0 or (days == 0 and hours == 0):
        parts.append(f"{minutes} Minute{'s' if minutes != 1 else ''}")
    parts.append(f"{seconds} Second{'s' if seconds != 1 else ''}")

    return ", ".join(parts)


def _ban_build_formatted(data):
    lines = [
        "╔══════════════════════════════╗",
        "║     BANCHECK INFORMATION      ║",
        "╚══════════════════════════════╝",
        f"├─ UID      : {data['uid']}",
        f"├─ Username : {data['username']}",
        f"├─ Region   : {data['region']}",
        f"├─ Level    : {data['level']}",
        f"├─ Likes    : {data['likes']}",
    ]

    if data["status"] == "Not Banned":
        lines.append("└─ Status   : ✅ Not Banned")
    else:
        lines.append("├─ Status   : ⛔ BANNED")
        if data.get("ban_date"):
            lines.append(f"├─ Ban Date : {data['ban_date']}")
            lines.append(f"└─ Since    : {data['since']}")
        else:
            lines.append("└─ Ban Date : N/A")

    return "\n".join(lines)


def _ban_check_player_info(target_id):
    uid = str(target_id).strip()
    if not uid.isdigit():
        return {"error": "Invalid UID format. UID must be numeric."}

    try:
        ban_res = requests.get(
            f"{GARENA_ANTIHACK_URL}?lang=en&uid={uid}",
            headers=GARENA_HEADERS,
            timeout=16
        )
        ban_json = ban_res.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to connect to Garena API: {str(e)}"}
    except Exception as e:
        return {"error": f"Error parsing Garena API response: {str(e)}"}

    if ban_json.get("status") == "error":
        msg = ban_json.get("msg", "")
        if "WRONG_ACCOUNT" in msg:
            return {"error": "ID NOT FOUND"}
        return {"error": f"Garena API error: {msg}"}

    ban_data = ban_json.get("data", {}) or {}
    is_banned = ban_data.get("is_banned", 0)

    username = "N/A"
    region = "N/A"
    level = "N/A"
    likes = 0
    last_login_ts = None

    try:
        region_used, info_data = asyncio.run(_try_regions(uid))
        basic = info_data.get('basicInfo', {}) or {}
        
        if basic.get('nickname'):
            username = basic.get('nickname')
        if basic.get('region'):
            region = basic.get('region').upper()
        elif region_used:
            region = region_used.upper()
        if basic.get('level') is not None:
            level = basic.get('level')
        if basic.get('liked') is not None:
            likes = basic.get('liked')
        if basic.get('lastLoginAt'):
            last_login_ts = int(basic.get('lastLoginAt'))
    except Exception as e:
        app.logger.warning(f"[bancheck] info fetch failed: {e}")

    now_bdt = dt.now(timezone(timedelta(hours=6)))
    ban_date_str = None
    since_str = None
    unban_time_str = None

    if is_banned:
        if last_login_ts:
            dt_utc = dt.fromtimestamp(last_login_ts, tz=timezone.utc)
            login_bdt = dt_utc.astimezone(timezone(timedelta(hours=6)))
            
            ban_date_str = format_timestamp_bst(last_login_ts)
            elapsed_seconds = max(0, int((now_bdt - login_bdt).total_seconds()))
            since_str = _ban_format_duration(elapsed_seconds)
        
        status = "Permanent"
        unban_time_str = None
    else:
        status = "Not Banned"

    return {
        "uid": uid,
        "username": username,
        "region": region,
        "level": level,
        "likes": likes,
        "status": status,
        "is_banned": bool(is_banned),
        "ban_date": ban_date_str,
        "since": since_str,
        "unban_time": unban_time_str,
    }


@app.route('/bancheck', methods=['GET'])
def check_ban_status():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "UID parameter is required"}), 400

    result = _ban_check_player_info(uid)
    if "error" in result:
        return jsonify(result), 404

    output_format = request.args.get('format', 'json').lower()
    if output_format in ('text', 'tree', 'raw'):
        return Response(_ban_build_formatted(result), mimetype='text/plain; charset=utf-8')

    return jsonify(result)



@app.route('/decode', methods=['GET'])
def decode_jwt_endpoint():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token parameter is required"}), 400

    parts = token.split('.')
    if len(parts) != 3:
        return jsonify({"error": "Invalid JWT format"}), 400

    def decode_base64(data):
        try:
            data += '=' * (-len(data) % 4)  # Add padding
            return json.loads(base64.urlsafe_b64decode(data).decode('utf-8'))
        except Exception as e:
            return {"error": f"Failed to decode token: {str(e)}"}

    payload = decode_base64(parts[1])
    if "error" in payload:
        return jsonify(payload), 400

    try:
        if 'exp' in payload and isinstance(payload['exp'], (int, float)):
            payload['exp_date'] = datetime.utcfromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S')
        if 'lock_region_time' in payload and isinstance(payload['lock_region_time'], (int, float)):
            payload['lock_region_date'] = datetime.utcfromtimestamp(payload['lock_region_time']).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass

    return jsonify(payload), 200



DASHBOARD_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">\n<meta name="theme-color" content="#090d20"><meta name="description" content="SHAPPNO API control center">\n<title>SHAPPNO — API Control Center</title>\n<style>\n:root{--bg:#080c1b;--panel:rgba(20,27,54,.76);--line:rgba(155,174,255,.17);--muted:#9ca9cb;--white:#f6f8ff;--cyan:#64e8ff;--violet:#a98bff;--green:#60f2b0;--red:#ff637d}\n*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(ellipse at 12% 0%,#25245a 0,transparent 36%),radial-gradient(ellipse at 90% 15%,#123c59 0,transparent 30%),var(--bg);color:var(--white);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh;overflow-x:hidden}\nbody:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 80%)}\n.wrap{width:min(1420px,calc(100% - 34px));margin:auto;position:relative;z-index:1}\n.top{display:flex;align-items:center;justify-content:space-between;padding:24px 0}.brand{display:flex;gap:12px;align-items:center;font-weight:900;letter-spacing:2px}.logo{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#62eaff,#a88bff);color:#071021;font-weight:1000;box-shadow:0 0 30px #65dfff55}\n.pill{border:1px solid var(--line);background:#ffffff09;border-radius:999px;padding:9px 13px;color:#b9c7e8;font-size:12px}.hero{padding:42px 0 32px;display:grid;grid-template-columns:1.4fr .6fr;gap:24px;align-items:center}.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:3px;font-weight:800}.hero h1{font-size:clamp(38px,6vw,72px);line-height:.98;margin:14px 0 16px;letter-spacing:-3px}.grad{background:linear-gradient(90deg,#6ceaff,#a78bff 55%,#ff9fcf);background-clip:text;color:transparent}.hero p{max-width:660px;color:var(--muted);line-height:1.7;margin:0}.hero-side{border:1px solid var(--line);background:linear-gradient(145deg,#ffffff10,#ffffff04);border-radius:24px;padding:22px;box-shadow:0 20px 70px #0005;backdrop-filter:blur(18px)}.stat{font-size:38px;font-weight:900;letter-spacing:-2px}.stat small{font-size:13px;color:var(--muted);letter-spacing:0;font-weight:600}.side-row{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin-top:14px}.bar{height:6px;border-radius:10px;background:#ffffff12;margin-top:8px;overflow:hidden}.bar i{display:block;width:100%;height:100%;background:linear-gradient(90deg,var(--cyan),var(--violet));border-radius:10px}\n.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;margin:24px 0 16px;flex-wrap:wrap}.search{flex:1;min-width:220px;max-width:440px;background:#ffffff0a;border:1px solid var(--line);border-radius:14px;padding:13px 16px;color:white;outline:none}.search:focus,input:focus{border-color:#71dfff88;box-shadow:0 0 0 3px #71dfff15}.count{color:var(--muted);font-size:12px}\n.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;padding-bottom:34px}.api-card{--accent:#6ceaff;position:relative;overflow:hidden;border:1px solid var(--line);border-radius:21px;padding:19px;background:linear-gradient(145deg,rgba(28,37,72,.88),rgba(13,19,41,.88));box-shadow:0 12px 38px #0003;transition:transform .25s,border-color .25s,box-shadow .25s;backdrop-filter:blur(12px)}.api-card:before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.9}.api-card:hover{transform:translateY(-4px);border-color:color-mix(in srgb,var(--accent),transparent 48%);box-shadow:0 18px 42px #0005}.card-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.api-name{font-size:17px;font-weight:800}.path{display:inline-block;margin-top:7px;color:var(--accent);font:11px ui-monospace,monospace;background:#ffffff0a;border:1px solid #ffffff12;border-radius:7px;padding:5px 8px}.desc{color:var(--muted);font-size:12px;line-height:1.5;margin:12px 0 15px;min-height:18px}.method{font-size:10px;font-weight:900;letter-spacing:1px;border:1px solid #62eaff44;color:var(--cyan);padding:5px 8px;border-radius:7px}.fields{display:grid;grid-template-columns:1fr 1fr;gap:10px}.field label{display:block;color:#aebbdc;font-size:10px;margin:0 0 6px}.field input{width:100%;min-width:0;border:1px solid #ffffff18;background:#070d20a8;color:white;border-radius:10px;padding:10px;font-size:12px;outline:none}.actions{display:flex;gap:8px;margin-top:14px}.btn{border:0;border-radius:10px;padding:10px 13px;font-size:11px;font-weight:800;cursor:pointer;transition:.2s}.call{flex:1;color:#061020;background:linear-gradient(100deg,var(--accent),#b9a4ff)}.example{color:#c4cdef;background:#ffffff0d;border:1px solid #ffffff17}.btn:hover{filter:brightness(1.12);transform:translateY(-1px)}.btn:disabled{opacity:.55;cursor:wait;transform:none}.result{display:none;margin-top:13px;border:1px solid #ffffff16;background:#060a16;border-radius:12px;overflow:hidden}.result.show{display:block}.result-head{display:flex;justify-content:space-between;align-items:center;padding:9px 11px;color:#aab8dc;font-size:10px;border-bottom:1px solid #ffffff12}.result pre{white-space:pre-wrap;word-break:break-word;max-height:260px;overflow:auto;margin:0;padding:12px;color:#dce7ff;font:11px/1.6 ui-monospace,monospace}.result img{display:block;max-width:100%;max-height:260px;margin:10px auto;border-radius:8px}.copy{border:0;background:none;color:var(--cyan);cursor:pointer;font-size:10px}\n.logs{border:1px solid var(--line);border-radius:20px;background:#10172dba;padding:18px;margin:4px 0 42px}.log-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.log-title h2{font-size:15px;margin:0}.log-list{display:flex;flex-direction:column;gap:7px;max-height:230px;overflow:auto}.log{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-radius:9px;background:#ffffff06;font:11px ui-monospace,monospace}.log .time{color:#7f8eaf;white-space:nowrap}.log .msg{font-weight:800}.log .detail{color:#b9c6e3;white-space:pre-wrap;word-break:break-word}.footer{padding:20px 0 35px;text-align:center;color:#7180a4;font-size:11px}.bubble{position:fixed;width:9px;height:9px;border-radius:50%;pointer-events:none;z-index:99;background:var(--cyan);animation:pop 1s cubic-bezier(.16,.75,.25,1) forwards;box-shadow:0 0 14px currentColor,0 0 28px currentColor}\n.bubble:nth-child(3n){border-radius:2px;transform:rotate(45deg)}.bubble:nth-child(4n){width:5px;height:5px}\n@keyframes pop{0%{transform:translate(0,0) scale(.2) rotate(0);opacity:0}12%{opacity:1;transform:translate(0,0) scale(1.25) rotate(45deg)}100%{transform:translate(var(--x),var(--y)) scale(0) rotate(260deg);opacity:0}}\n.bubble-ring{position:fixed;z-index:98;pointer-events:none;width:12px;height:12px;border:1px solid #7cecff;border-radius:50%;transform:translate(-50%,-50%);animation:ringOut .75s ease-out forwards;box-shadow:0 0 18px #6ceaff88}\n@keyframes ringOut{to{width:125px;height:125px;opacity:0;border-width:0}}\n\n.splash{position:fixed;inset:0;z-index:1000;background:#070b19;display:grid;place-items:center;transition:opacity .8s,visibility .8s}.splash.hide{opacity:0;visibility:hidden}.splash-word{font-size:clamp(40px,10vw,100px);font-weight:1000;letter-spacing:8px;background:linear-gradient(110deg,#5feaff,#a58aff,#ff9bc8,#60f2b0,#5feaff);background-size:400% 100%;background-clip:text;color:transparent;animation:shine 2.2s linear infinite,zoom 1.2s ease both,glowPulse 1.8s ease-in-out infinite alternate,letterFloat 3.4s ease-in-out infinite;text-shadow:0 0 55px #6ceaff25;filter:drop-shadow(0 0 20px #6ceaff55);position:relative}\n.splash-word:after{content:"SHAPPNO";position:absolute;inset:0;background:linear-gradient(90deg,transparent,#ffffffd9,transparent);background-size:200% 100%;background-clip:text;color:transparent;animation:scan 2.8s ease-in-out infinite;mix-blend-mode:screen}\n@keyframes glowPulse{from{filter:drop-shadow(0 0 8px #6ceaff55)}to{filter:drop-shadow(0 0 34px #b58cffaa)}}\n@keyframes letterFloat{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-9px) scale(1.035)}}\n@keyframes scan{0%,15%{background-position:-120% 0}70%,100%{background-position:120% 0}}\n@keyframes shine{to{background-position:250%}}@keyframes zoom{from{opacity:0;transform:scale(.65);filter:blur(12px)}to{opacity:1;transform:scale(1);filter:blur(0)}}\n@media(max-width:1050px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{grid-template-columns:1fr .6fr}}@media(max-width:700px){.wrap{width:calc(100% - 22px)}.hero{grid-template-columns:1fr;padding-top:24px}.hero-side{display:none}.grid{grid-template-columns:1fr}.top{padding:16px 0}.hero h1{letter-spacing:-2px}.fields{gap:9px}.api-card{padding:16px}}\n\n.api-card{transition:transform .28s cubic-bezier(.2,.8,.2,1),border-color .28s,box-shadow .28s}\n.api-card:hover{transform:translateY(-6px) scale(1.008)}\n.logo{animation:logoBreath 3s ease-in-out infinite;position:relative}.brand>span{background:linear-gradient(90deg,#f6f8ff,#69eaff,#c4a7ff,#f6f8ff);background-size:250%;background-clip:text;color:transparent;animation:shine 4s linear infinite}\n@keyframes logoBreath{0%,100%{box-shadow:0 0 18px #65dfff44,0 0 0 0 #65dfff22}50%{box-shadow:0 0 34px #65dfff99,0 0 0 7px #65dfff08}}\n.btn{position:relative;overflow:hidden}.btn:after{content:"";position:absolute;inset:-80% auto -80% -35%;width:28%;background:#ffffff55;transform:rotate(25deg);transition:left .45s}.btn:hover:after{left:125%}\n@media(max-width:700px){.hero{padding-bottom:18px}.api-card{border-radius:18px}.toolbar{margin-top:12px}}\n\n/* SHAPPNO refreshed interface */\n:root{--bg:#070b16;--panel:rgba(17,26,49,.82);--line:rgba(137,170,220,.19);--muted:#a8b6d1;--white:#f4f8ff;--cyan:#72e7ff;--violet:#a99bff;--green:#50e69b}\nbody{background:radial-gradient(ellipse at 8% -8%,#253b68 0,transparent 38%),radial-gradient(ellipse at 94% 8%,#123f49 0,transparent 32%),linear-gradient(145deg,#070b16,#0b1224 58%,#080d1b)}\n.top{padding:22px 0 18px}.logo{border-radius:50%;background:linear-gradient(145deg,#6fffd0,#19b879);color:#062418;box-shadow:0 0 22px #38e89a55}\n.pill{display:flex;align-items:center;gap:9px;background:#0d1c20;border-color:#36d88b55;color:#b8f8d7;font-weight:800;letter-spacing:1px}\n.online-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#35e68b;box-shadow:0 0 0 4px #35e68b20,0 0 13px #35e68b;flex:0 0 auto}\n.hero{padding-top:36px}.hero-side,.api-card,.logs{background:linear-gradient(145deg,rgba(22,35,63,.92),rgba(10,18,36,.94));border-color:rgba(145,174,225,.2);box-shadow:0 16px 44px #0004}\n.api-card{border-radius:19px;transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease}\n.api-card:hover{transform:translateY(-3px);box-shadow:0 18px 38px #0005}\n.search,.field input{background:#080f20;border-color:#ffffff1c}.search{border-radius:13px}\n.btn{border-radius:11px;letter-spacing:.35px}.call{background:linear-gradient(105deg,var(--accent),#c2b7ff)}\n.example{background:#ffffff0b}.result{background:#070c18}\n.urls-panel{display:flex;align-items:center;justify-content:space-between;gap:18px;margin:0 0 26px;padding:22px;border:1px solid #6fe7ff2b;border-radius:20px;background:linear-gradient(120deg,#10243a,#151b38 70%,#102b2c);box-shadow:0 16px 38px #0004}\n.urls-panel h2{font-size:18px;letter-spacing:.5px;margin:7px 0}.urls-panel p{font-size:12px;color:var(--muted);margin:0;line-height:1.5}\n.all-urls-btn{background:linear-gradient(110deg,#53e6b0,#69dfff);color:#061b20;padding:13px 19px;white-space:nowrap;box-shadow:0 7px 22px #38dca52a}\n\n\n\n\n\n.bubble{width:7px;height:7px;animation:pop .72s cubic-bezier(.2,.65,.3,1) forwards;box-shadow:0 0 8px currentColor}\n@keyframes pop{0%{transform:translate(0,0) scale(.35);opacity:0}18%{opacity:.8;transform:translate(0,0) scale(1)}100%{transform:translate(var(--x),var(--y)) scale(.25);opacity:0}}\n.bubble-ring{width:9px;height:9px;animation:ringOut .55s ease-out forwards;box-shadow:0 0 10px #6ceaff55}\n@keyframes ringOut{to{width:72px;height:72px;opacity:0;border-width:0}}\n@media(max-width:700px){.urls-panel{align-items:stretch;flex-direction:column}.all-urls-btn{width:100%}.splash-word{letter-spacing:6px}}\n\n\n/* SHAPPNO motion pack + dashboard-wide visual refresh */\n.splash{background:radial-gradient(circle at 50% 48%,#17264b 0,#090e20 42%,#050711 100%);overflow:hidden}\n.splash:before,.splash:after{content:"";position:absolute;width:min(78vw,620px);aspect-ratio:1;border:1px solid #73eaff26;border-radius:50%;box-shadow:0 0 70px #6ceaff12,inset 0 0 70px #a78bff10;animation:orbitA 5s ease-in-out infinite}\n.splash:after{width:min(58vw,440px);border-color:#c49aff30;animation:orbitB 4s ease-in-out infinite}\n.splash-word{z-index:1;animation:shine 2.2s linear infinite,zoom 1.2s ease both,glowPulse 1.8s ease-in-out infinite alternate,letterFloat 3.4s ease-in-out infinite,wordTilt 5s ease-in-out infinite}\n.splash-word.mode-flip{animation:flipIn 1.15s cubic-bezier(.2,.8,.2,1) both,shine 2s linear infinite}.splash-word.mode-glitch{animation:glitchIn .9s steps(2,end) both,shine 2s linear infinite}.splash-word.mode-pop{animation:popIn .95s cubic-bezier(.16,1,.3,1) both,shine 2s linear infinite}.splash-word.mode-wave{animation:waveIn 1.2s ease both,shine 2s linear infinite}\n@keyframes orbitA{0%,100%{transform:scale(.88) rotate(0);opacity:.35}50%{transform:scale(1.08) rotate(160deg);opacity:.85}}@keyframes orbitB{0%,100%{transform:scale(1.1) rotate(0);opacity:.25}50%{transform:scale(.82) rotate(-150deg);opacity:.75}}\n@keyframes wordTilt{0%,100%{rotate:0deg}25%{rotate:-1.5deg}75%{rotate:1.5deg}}@keyframes flipIn{from{opacity:0;transform:perspective(700px) rotateX(-85deg) scale(.7);filter:blur(9px)}to{opacity:1;transform:perspective(700px) rotateX(0) scale(1);filter:blur(0)}}\n@keyframes glitchIn{0%{opacity:0;transform:translateX(-18px) skewX(18deg);text-shadow:5px 0 #ff5ca8,-5px 0 #5feaff}55%{opacity:1;transform:translateX(5px) skewX(-8deg)}100%{transform:translateX(0) skewX(0);text-shadow:none}}@keyframes popIn{0%{opacity:0;transform:scale(.15);filter:blur(18px)}70%{opacity:1;transform:scale(1.12)}100%{transform:scale(1);filter:blur(0)}}@keyframes waveIn{0%{opacity:0;transform:translateY(55px) rotateX(65deg);letter-spacing:22px}100%{opacity:1;transform:translateY(0) rotateX(0);letter-spacing:8px}}\n.api-card,.hero-side,.logs,.search,.field input,.pill,.btn,.result{backdrop-filter:blur(14px)}.api-card{animation:cardRise .65s both}.api-card:nth-child(3n+2){animation-delay:.07s}.api-card:nth-child(3n){animation-delay:.14s}\n@keyframes cardRise{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}.field input{transition:border-color .22s,box-shadow .22s,background .22s,transform .22s}.field input:focus{transform:translateY(-1px);background:#0c1630}.search{transition:border-color .22s,box-shadow .22s,transform .22s}.search:focus{transform:translateY(-1px)}.btn:active{transform:scale(.97)}\n.result.show{animation:resultIn .3s ease both}@keyframes resultIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}\n</style></head>\n<body>\n<div class="splash" id="splash"><div class="splash-word">SHAPPNO</div></div>\n<div class="wrap">\n<header class="top"><div class="brand"><div class="logo">S</div><span>SHAPPNO <span style="color:#6ceaff">API</span></span></div><div class="pill"><span class="online-dot"></span>SYSTEM ONLINE</div></header>\n<section class="hero"><div><div class="eyebrow">POWERFUL · FAST · SIMPLE</div><h1>API CONTROL<br><span class="grad">CENTER.</span></h1></div><div class="hero-side"><div class="eyebrow">AVAILABLE ENDPOINTS</div><div class="stat"><span id="apiCount">22</span> <small>API SERVICES</small></div><div class="side-row"><span>API workspace</span><span>READY</span></div><div class="bar"><i></i></div><div class="side-row"><span>Live response viewer</span><span>ENABLED</span></div></div></section>\n<div class="toolbar"><input class="search" id="search" placeholder="⌕  Search API name or endpoint..." autocomplete="off"><span class="count" id="visibleCount"></span></div>\n<main class="grid" id="apiGrid"></main>\n<section class="urls-panel"><div><div class="eyebrow">QUICK COPY</div><h2>SHAPPNO API URLS</h2><p>Copy the complete endpoint list with its original spacing.</p></div><button class="btn all-urls-btn" id="copyAllUrls">ALL URLS COPY</button></section>\n\n\n</div>\n<script>\nconst APIS=[{"name":"ACCESS TOKEN","path":"/access","desc":"Generate access credentials","fields":[["uid","UID","123456789"],["password","Password","YOUR_PASSWORD"]]},{"name":"JWT TOKEN","path":"/token","desc":"Create a region-based JWT token","fields":[["uid","UID","123456789"],["password","Password","YOUR_PASSWORD"]]},{"name":"PLAYER INFO","path":"/info","desc":"Full player profile and account details","fields":[["uid","UID","123456789"]]},{"name":"LEVEL INFO","path":"/level","desc":"Player level information","fields":[["uid","UID","123456789"]]},{"name":"REGION INFO","path":"/region","desc":"Detect account region","fields":[["uid","UID","123456789"]]},{"name":"LEADER INFO","path":"/leader","desc":"Player leader information","fields":[["uid","UID","123456789"]]},{"name":"WISHLIST","path":"/wishlist","desc":"Get player wishlist items","fields":[["uid","UID","123456789"]]},{"name":"OUTFIT","path":"/shappno-outfit","desc":"Generate outfit preview","fields":[["uid","UID","123456789"]]},{"name":"ADD FRIEND","path":"/add_friend","desc":"Send a friend request","fields":[["uid","Account UID","123456789"],["password","Account Password","YOUR_PASSWORD"],["friend_uid","Target UID","987654321"],["server_name","Server (optional)","BD"]]},{"name":"REMOVE FRIEND","path":"/rv_friend","desc":"Remove a friend from the account","fields":[["uid","Account UID","123456789"],["password","Account Password","YOUR_PASSWORD"],["friend_uid","Friend UID","987654321"],["server_name","Server (optional)","BD"]]},{"name":"SPAM RQ SEND","path":"/shappno-send","desc":"Send requests through configured account lists","fields":[["uid","Target UID","123456789"],["region","Region: bd / ind","bd"]]},{"name":"BANNER","path":"/shappno-banner","desc":"Create a player banner image","fields":[["uid","UID","123456789"]],"image":true},{"name":"DYNAMIC DUO","path":"/duo-ck","desc":"Dynamic Duo partner and progress details","fields":[["uid","UID","123456789"]]},{"name":"JOIN GUILD","path":"/request_clan","desc":"Send a clan join request","fields":[["clan_id","Clan ID","123456"],["jwt","JWT (optional)","YOUR_JWT"],["uid","UID (optional)","123456789"],["pass","Password (optional)","YOUR_PASSWORD"],["region","Region (optional)","BD"]]},{"name":"QUIT GUILD","path":"/quit_clan","desc":"Leave a clan","fields":[["clan_id","Clan ID","123456"],["jwt","JWT (optional)","YOUR_JWT"],["uid","UID (optional)","123456789"],["pass","Password (optional)","YOUR_PASSWORD"],["region","Region (optional)","BD"]]},{"name":"GUEST NICKNAME CHANGE","path":"/guest","desc":"Guest account nickname action","fields":[["uid","UID","123456789"],["password","Password","YOUR_PASSWORD"],["name","Nickname","SHAPPNO"],["region","Region (optional)","BD"]]},{"name":"JWT TO NICKNAME CHANGE","path":"/jwt-to-change","desc":"Change nickname using JWT","fields":[["jwt","JWT","YOUR_JWT"],["name","New nickname","SHAPPNO"],["region","Region (optional)","BD"]]},{"name":"EMOTE EQUIP","path":"/emote-eq","desc":"Equip an emote using account login","fields":[["uid","UID","123456789"],["password","Password","YOUR_PASSWORD"],["emote_enquip","Emote value","1"],["region","Region (optional)","BD"]]},{"name":"BAN CHECK","path":"/bancheck","desc":"Check account ban status","fields":[["uid","UID","123456789"]]},{"name":"JWT Decode","path":"/decode","desc":"DECODE JWT payload and timestamps","fields":[["token","JWT Token","YOUR_JWT"]]},{"name":"ITEM ","path":"/item","desc":"Get an item icon image by item ID","fields":[["id","Item ID","909000010"]],"image":true},{"name":"BIO UPLOAD","path":"/bio_upload","desc":"Update account bio using JWT or login details","fields":[["bio","Bio text","Hello from SHAPPNO"],["jwt","JWT (optional)","YOUR_JWT"],["uid","UID (optional)","123456789"],["password","Password (optional)","YOUR_PASSWORD"],["access","Access token (optional)","YOUR_ACCESS_TOKEN"]],"method":"GET"}];\nconst palette=[\'#63eaff\',\'#a98bff\',\'#60f2b0\',\'#ff9fcf\',\'#ffc46b\',\'#7eafff\',\'#ff7e9c\',\'#74e3cb\'];\nconst grid=document.getElementById(\'apiGrid\');\ndocument.getElementById(\'apiCount\').textContent=APIS.length;\nfunction escapeHtml(s){return String(s).replace(/[&<>"\']/g,c=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',\'"\':\'&quot;\',"\'":\'&#39;\'}[c]));}\nfunction addLog(){}\nfunction render(){const q=document.getElementById(\'search\').value.toLowerCase();const filtered=APIS.filter(a=>(a.name+\' \'+a.path+\' \'+a.desc).toLowerCase().includes(q));document.getElementById(\'visibleCount\').textContent=`${filtered.length} / ${APIS.length} APIs`;grid.innerHTML=filtered.map((a)=>{const idx=APIS.indexOf(a),accent=palette[idx%palette.length];return `<article class="api-card" style="--accent:${accent}" data-path="${a.path}"><div class="card-head"><div><div class="api-name">${escapeHtml(a.name)}</div><span class="path">${escapeHtml(a.path)}</span></div><span class="method">${a.method||\'GET\'}</span></div><p class="desc">${escapeHtml(a.desc)}</p><div class="fields">${a.fields.map(([key,label,example])=>`<div class="field"><label>${escapeHtml(label)}</label><input data-key="${escapeHtml(key)}" placeholder="${escapeHtml(example)}" ${[\'password\',\'pass\',\'jwt\',\'token\',\'access\'].includes(key)?\'type="password"\':\'\'}></div>`).join(\'\')}</div><div class="actions"><button class="btn example" data-copy-url="${idx}">COPY URL</button><button class="btn call" data-call="${idx}">CALL API ↗</button></div><div class="result" id="result-${idx}"><div class="result-head"><span>API RESPONSE</span><button class="copy" data-copy="${idx}">COPY RESPONSE</button></div><pre></pre></div></article>`}).join(\'\');}\nfunction burst(el){const r=el.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2;const ring=document.createElement(\'i\');ring.className=\'bubble-ring\';ring.style.left=x+\'px\';ring.style.top=y+\'px\';document.body.appendChild(ring);setTimeout(()=>ring.remove(),600);for(let i=0;i<12;i++){const b=document.createElement(\'i\');b.className=\'bubble\';b.style.left=x+\'px\';b.style.top=y+\'px\';const angle=(Math.PI*2*i/12)+(Math.random()-.5)*.35,dist=24+Math.random()*58;b.style.setProperty(\'--x\',(Math.cos(angle)*dist)+\'px\');b.style.setProperty(\'--y\',(Math.sin(angle)*dist)+\'px\');b.style.background=palette[i%palette.length];document.body.appendChild(b);setTimeout(()=>b.remove(),760);}}\nasync function callApi(idx,button){const api=APIS[idx],card=button.closest(\'.api-card\'),params=new URLSearchParams();card.querySelectorAll(\'input\').forEach(input=>{if(input.value.trim())params.set(input.dataset.key,input.value.trim());});if(!params.toString()){addLog(api.name,false,\'Fill the required parameters first.\');return;}button.disabled=true;button.textContent=\'CALLING...\';const result=document.getElementById(`result-${idx}`);result.classList.add(\'show\');const pre=result.querySelector(\'pre\');pre.textContent=\'Connecting to API...\';try{const response=await fetch(api.path+\'?\'+params.toString(),{method:api.method||\'GET\',headers:{\'Accept\':\'application/json, text/plain, */*\'}});const type=response.headers.get(\'content-type\')||\'\';if(type.includes(\'image/\')){const blob=await response.blob(),url=URL.createObjectURL(blob);pre.innerHTML=\'\';const img=document.createElement(\'img\');img.src=url;pre.appendChild(img);addLog(api.name,response.ok,`${response.status} · image response`);result.dataset.response=\'Image response\';}else{const body=await response.text();let pretty=body;try{pretty=JSON.stringify(JSON.parse(body),null,2)}catch{}pre.textContent=pretty;result.dataset.response=pretty;if(response.ok)addLog(api.name,true,`${response.status} · ${api.path}`);else addLog(api.name,false,`${response.status} · ${pretty}`);}}catch(err){pre.textContent=String(err);result.dataset.response=String(err);addLog(api.name,false,String(err));}finally{button.disabled=false;button.textContent=\'CALL API ↗\';}}\ngrid.addEventListener(\'click\',e=>{const urlBtn=e.target.closest(\'[data-copy-url]\');if(urlBtn){const idx=+urlBtn.dataset.copyUrl,card=urlBtn.closest(\'.api-card\'),params=new URLSearchParams();card.querySelectorAll(\'input\').forEach(input=>{if(input.value.trim())params.set(input.dataset.key,input.value.trim());});const fullUrl=location.origin+APIS[idx].path+(params.toString()?\'?\'+params.toString():\'\');if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(fullUrl).then(()=>{urlBtn.textContent=\'COPIED ✓\';setTimeout(()=>urlBtn.textContent=\'COPY URL\',1200)}).catch(()=>window.prompt(\'Copy API URL\',fullUrl));}else{window.prompt(\'Copy API URL\',fullUrl);}return;}const call=e.target.closest(\'[data-call]\');if(call){callApi(+call.dataset.call,call);return;}const cp=e.target.closest(\'[data-copy]\');if(cp){const r=document.getElementById(`result-${cp.dataset.copy}`);const t=r.dataset.response||r.querySelector(\'pre\').innerText;navigator.clipboard?.writeText(t);cp.textContent=\'COPIED\';setTimeout(()=>cp.textContent=\'COPY RESPONSE\',1000);}});\n\nconst ALL_URLS_TEXT="SHAPPNO APIS\\n\\n1. ACCESS TOKEN\\n   http://127.0.0.1:5000/access?uid=YOUR_UID&password=YOUR_PASSWORD\\n\\n2. JWT  TOKEN\\n   http://127.0.0.1:5000/token?uid=YOUR_UID&password=YOUR_PASSWORD\\n\\n3. INFO\\n   http://127.0.0.1:5000/info?uid=YOUR_UID\\n\\n4. LEVEL INFO\\n   http://127.0.0.1:5000/level?uid=YOUR_UID\\n\\n5. REGION INFO\\n   http://127.0.0.1:5000/region?uid=YOUR_UID\\n\\n6. LEADER INFO\\n   http://127.0.0.1:5000/leader?uid=YOUR_UID\\n\\n7. WISHLIST INFO (PICTURE)\\n   http://127.0.0.1:5000/wishlist?uid=YOUR_UID\\n\\n8. OUTFIT INFO\\n   http://127.0.0.1:5000/shappno-outfit?uid=YOUR_UID\\n\\n9. ADD FRIEND\\n   http://127.0.0.1:5000/add_friend?uid=YOUR_UID&password=YOUR_PASSWORD&friend_uid=TARGET_UID\\n\\nhttp://127.0.0.1:5000/add_friend?uid=YOUR_UID&password=YOUR_PASSWORD&friend_uid=TARGET_UID&server_name=REGION\\n\\n10. REMOVE FRIEND\\n    http://127.0.0.1:5000/rv_friend?uid=YOUR_UID&password=YOUR_PASSWORD&friend_uid=TARGET_UID\\n\\n11. FRIEND RQ SEND SPAM\\n    http://127.0.0.1:5000/shappno-send?uid=YOUR_UID&region=REGION\\n\\n12. SHAPPNO BANNER (PICTURE)\\n    http://127.0.0.1:5000/shappno-banner?uid=YOUR_UID\\n\\n13. DUO INFO\\n    http://127.0.0.1:5000/duo-ck?uid=YOUR_UID\\n\\n14. REQUEST CLAN (GUILD RQ)\\n    http://127.0.0.1:5000/request_clan?uid=YOUR_UID&pass=YOUR_PASS&clan_id=CLAN_ID\\n\\nhttp://127.0.0.1:5000/request_clan?uid=YOUR_UID&pass=YOUR_PASSWORD&clan_id=CLAN_ID&region=REGION\\n\\n16. QUIT CLAN (GUILD LEAVE)\\n    http://127.0.0.1:5000/quit_clan?uid=YOUR_UID&pass=YOUR_PASS&clan_id=CLAN_ID\\n\\n17. GUEST (NAME CHANGE)\\n    http://127.0.0.1:5000/guest?uid=YOUR_UID&password=YOUR_PASS&name=NEW_NAME\\n\\nhttp://127.0.0.1:5000/guest?uid=YOUR_UID&password=YOUR_PASSWORD&name=YOUR_NAME&region=REGION\\n\\n18. JWT ( NMAE CHANGE)\\n    http://127.0.0.1:5000/jwt-to-change?jwt=YOUR_JWT&name=YOUR_NAME\\n\\n19. EMOTE EQUIPMENT (FF EMOTE EQ)\\n  http://127.0.0.1:5000/emote-eq?uid=YOUR_UID&password=YOUR_PASS&emote_enquip=1\\n\\nhttp://127.0.0.1:5000/emote-eq?uid=YOUR_UID&password=YOUR_PASSWORD&emote_enquip=1&region=YOUR_REGION\\n\\n19. BAN CHECK INFO\\n    http://127.0.0.1:5000/bancheck?uid=YOUR_UID\\n\\n20. DECODE JWT\\n    http://127.0.0.1:5000/decode?token=YOUR_JWT_TOKEN\\n\\n21. BIO UPLOAD\\n    http://127.0.0.1:5000/bio_upload?uid=YOUR_UID&pass=YOUR_PASS&bio=Hello-fck\\n\\nhttp://127.0.0.1:5000/bio_upload?jwt=YOUR_JWT&bio=Hello-fck\\n\\nhttp://127.0.0.1:5000/bio_upload?access=YOUR_ACCESS_TOKEN&bio=Hello-fck";\nconst copyAllButton=document.getElementById(\'copyAllUrls\');\ncopyAllButton.addEventListener(\'click\',async()=>{\n  try{\n    if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(ALL_URLS_TEXT);}\n    else{\n      const area=document.createElement(\'textarea\');area.value=ALL_URLS_TEXT;\n      area.setAttribute(\'readonly\',\'\');area.style.position=\'fixed\';area.style.opacity=\'0\';\n      document.body.appendChild(area);area.select();\n      const copied=document.execCommand(\'copy\');area.remove();\n      if(!copied)throw new Error(\'Clipboard copy is not available\');\n    }\n    copyAllButton.textContent=\'COPIED ✓\';\n    setTimeout(()=>copyAllButton.textContent=\'ALL URLS COPY\',1400);\n  }catch(err){\n    const area=document.createElement(\'textarea\');area.value=ALL_URLS_TEXT;\n    area.style.position=\'fixed\';area.style.opacity=\'0\';document.body.appendChild(area);\n    area.select();document.execCommand(\'copy\');area.remove();\n    copyAllButton.textContent=\'COPIED ✓\';\n    setTimeout(()=>copyAllButton.textContent=\'ALL URLS COPY\',1400);\n  }\n});\n\ndocument.getElementById(\'search\').addEventListener(\'input\',render);\nrender();document.addEventListener(\'pointerdown\',e=>{const target=e.target.closest(\'button,.field input,.search\');if(target)burst(target);});window.addEventListener(\'load\',()=>{const splash=document.getElementById(\'splash\'),word=splash.querySelector(\'.splash-word\'),modes=[\'mode-flip\',\'mode-glitch\',\'mode-pop\',\'mode-wave\'];let n=0;const cycle=()=>{word.classList.remove(...modes);void word.offsetWidth;word.classList.add(modes[n++%modes.length]);};cycle();const motion=setInterval(()=>{if(splash.classList.contains(\'hide\')){clearInterval(motion);return;}cycle();},720);setTimeout(()=>splash.classList.add(\'hide\'),2900);});\n</script></body></html>'
@app.route("/")
def shappno_home():
    return Response(DASHBOARD_HTML, mimetype="text/html; charset=utf-8")


async def startup():
    asyncio.create_task(refresh_tokens_periodically())



if __name__ == '__main__':
    try:
        asyncio.run(startup())
    except Exception:
        pass
    app.run(host='0.0.0.0', port=50335, debug=True)