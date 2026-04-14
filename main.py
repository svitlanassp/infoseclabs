import os
import base64
import tempfile
from urllib.parse import quote
import aiofiles
from typing import Annotated

from fastapi import FastAPI, UploadFile, File, Form, Response, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from lab1 import lab1
from lab2.lab2 import MyMD5
from lab3.lab3 import RC5
from lab4.lab4 import RSA
from lab5.lab5 import DSA

LABEL_PRIVATE_KEY = "файл приватного ключа"
LABEL_PUBLIC_KEY = "файл публічного ключа"

app = FastAPI(title="InfoSec Labs")

app.mount("/static", StaticFiles(directory="static"), name="static")

# Helpers

def stream_file(path: str, background_tasks: BackgroundTasks, filename: str) -> StreamingResponse:
    def iterfile():
        with open(path, mode="rb") as f:
            yield from f

    background_tasks.add_task(os.remove, path)
    encoded_name = quote(filename)
    return StreamingResponse(
        iterfile(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}"},
    )


def load_key(tool, method: str, key_bytes: bytes, label: str) -> None:
    try:
        getattr(tool, method)(key_bytes)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Недійсний {label}!") from exc


# Root

@app.get("/")
def read_root():
    return FileResponse("static/index.html")


# Lab 1 — PRNG

class Lab1Request(BaseModel):
    m: int
    a: int
    c: int
    x0: int
    n: int


@app.post("/api/lab1/run", responses={400: {"description": "Некоректні параметри генератора"}})
def run_lab1(data: Lab1Request):
    if data.n < 2:
        raise HTTPException(status_code=400, detail="n must be ≥ 2")

    nums = lab1.generator(data.m, data.a, data.c, data.x0, data.n)
    my_pi = lab1.cesaro(nums)
    rand_pi = lab1.cesaro_rand(data.m, data.n)

    return {
        "my_pi": round(my_pi, 6),
        "rand_pi": round(rand_pi, 6),
        "preview": nums[:2000],
        "total": data.n,
    }


# Lab 2 — MD5

@app.post("/api/lab2/hash-string")
def hash_string(text: Annotated[str, Form()] = ""):
    return {"hash": MyMD5.hash_string(text)}


@app.post("/api/lab2/hash-file")
async def hash_file(file: Annotated[UploadFile, File(...)]):
    result = await MyMD5.hash_upload_file(file)
    return {"hash": result, "filename": file.filename}


@app.post("/api/lab2/verify-file")
async def verify_file(
    expected: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)]
):
    actual = await MyMD5.hash_upload_file(file)
    return {
        "is_ok": actual.lower() == expected.strip().lower(),
        "actual": actual,
        "filename": file.filename,
    }


@app.post("/api/lab2/download-report")
def download_report(result: Annotated[str, Form(...)]):
    return Response(
        content=result.strip(),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="md5_report.txt"'},
    )


# Lab 3 — RC5

@app.post("/api/lab3/encrypt", responses={500: {"description": "Помилка внутрішнього шифрування"}})
async def rc5_encrypt(
    background_tasks: BackgroundTasks,
    password: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)],
):
    rc5 = RC5(password=password)
    data = await file.read()

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        await tmp_in.write(data)
        in_path = tmp_in.name

    out_fd, out_path = tempfile.mkstemp(suffix=".enc")
    os.close(out_fd)

    try:
        rc5.encrypt_file(in_path, out_path)
    except Exception as exc:
        os.remove(in_path)
        os.remove(out_path)
        raise HTTPException(status_code=500, detail=f"Помилка шифрування: {exc}") from exc

    background_tasks.add_task(os.remove, in_path)
    return stream_file(out_path, background_tasks, f"{file.filename}.enc")


@app.post("/api/lab3/decrypt", responses={400: {"description": "Дешифрування неможливе (невірний пароль або файл)"}})
async def rc5_decrypt(
    background_tasks: BackgroundTasks,
    password: Annotated[str, Form(...)],
    file: Annotated[UploadFile, File(...)],
):
    rc5 = RC5(password=password)
    data = await file.read()

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp_in:
        await tmp_in.write(data)
        in_path = tmp_in.name

    out_fd, out_path = tempfile.mkstemp()
    os.close(out_fd)

    try:
        rc5.decrypt_file(in_path, out_path)
    except Exception as exc:
        os.remove(in_path)
        os.remove(out_path)
        raise HTTPException(status_code=400, detail=f"Дешифрування неможливе: {exc}") from exc

    background_tasks.add_task(os.remove, in_path)
    out_filename = f"decrypted_{file.filename.removesuffix('.enc')}"
    return stream_file(out_path, background_tasks, out_filename)


# Lab 4 — RSA

@app.post("/api/lab4/generate-keys")
def rsa_generate_keys():
    rsa = RSA(key_size=2048)
    rsa.generate_keys()
    return {
        "private": base64.b64encode(rsa.get_private_key_bytes()).decode(),
        "public":  base64.b64encode(rsa.get_public_key_bytes()).decode(),
    }


@app.post("/api/lab4/encrypt", responses={400: {"description": "Недійсний публічний ключ"}, 500: {"description": "Помилка шифрування"}})
async def rsa_encrypt(
    background_tasks: BackgroundTasks,
    key_file: Annotated[UploadFile, File(...)],
    data_file: Annotated[UploadFile, File(...)],
):
    rsa = RSA()
    load_key(rsa, "load_public_key",  await key_file.read(), LABEL_PUBLIC_KEY)

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        await tmp_in.write(await data_file.read())
        in_path = tmp_in.name

    out_fd, out_path = tempfile.mkstemp(suffix=".enc")
    os.close(out_fd)

    try:
        rsa.encrypt_file(in_path, out_path)
    except Exception as exc:
        os.remove(in_path)
        os.remove(out_path)
        raise HTTPException(status_code=500, detail=f"Помилка шифрування: {exc}") from exc

    background_tasks.add_task(os.remove, in_path)
    return stream_file(out_path, background_tasks, f"{data_file.filename}.enc")


@app.post("/api/lab4/decrypt", responses={400: {"description": "Недійсний приватний ключ або помилка дешифрування"}})
async def rsa_decrypt(
    background_tasks: BackgroundTasks,
    key_file: Annotated[UploadFile, File(...)],
    data_file: Annotated[UploadFile, File(...)],
):
    rsa = RSA()
    load_key(rsa, "load_private_key", await key_file.read(), LABEL_PRIVATE_KEY)

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp_in:
        await tmp_in.write(await data_file.read())
        in_path = tmp_in.name

    out_fd, out_path = tempfile.mkstemp()
    os.close(out_fd)

    try:
        rsa.decrypt_file(in_path, out_path)
    except Exception as exc:
        os.remove(in_path)
        os.remove(out_path)
        raise HTTPException(status_code=400, detail=f"Помилка при дешифруванні: {exc}") from exc

    background_tasks.add_task(os.remove, in_path)
    out_filename = data_file.filename.removesuffix(".enc") or "decrypted_file"
    return stream_file(out_path, background_tasks, out_filename)


# Lab 5 — DSA

@app.post("/api/lab5/generate-keys")
def dsa_generate_keys():
    dsa = DSA(key_size=2048)
    dsa.generate_keys()
    return {
        "private": base64.b64encode(dsa.get_private_key_bytes()).decode(),
        "public":  base64.b64encode(dsa.get_public_key_bytes()).decode(),
    }


@app.post("/api/lab5/sign-text", responses={400: {"description": "Недійсний приватний ключ"}, 500: {"description": "Помилка при підписанні"}})
async def dsa_sign_text(
    text: Annotated[str, Form(...)],
    key_file: Annotated[UploadFile, File(...)],
):
    dsa = DSA()
    load_key(dsa, "load_private_key", await key_file.read(), LABEL_PRIVATE_KEY)

    try:
        signature_hex = dsa.sign_text(text)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Помилка при підписанні: {exc}") from exc

    return StreamingResponse(
        iter([signature_hex.encode()]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename*=UTF-8''text_signature.sig"},
    )


@app.post("/api/lab5/verify-text", responses={400: {"description": "Недійсний публічний ключ або помилка перевірки"}})
async def dsa_verify_text(
    text: Annotated[str, Form(...)],
    sig_file: Annotated[UploadFile, File(...)],
    key_file: Annotated[UploadFile, File(...)],
):
    dsa = DSA()
    load_key(dsa, "load_public_key",  await key_file.read(), LABEL_PUBLIC_KEY)

    try:
        signature_hex = (await sig_file.read()).decode().strip()
        return {"valid": dsa.verify_text(text, signature_hex)}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Помилка при перевірці: {exc}") from exc


@app.post("/api/lab5/sign-file", responses={400: {"description": "Недійсний приватний ключ"}, 500: {"description": "Помилка при підписанні"}})
async def dsa_sign_file(
    background_tasks: BackgroundTasks,
    key_file: Annotated[UploadFile, File(...)],
    data_file: Annotated[UploadFile, File(...)],
):
    dsa = DSA()
    load_key(dsa, "load_private_key", await key_file.read(), LABEL_PRIVATE_KEY)

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        await tmp_in.write(await data_file.read())
        in_path = tmp_in.name

    out_fd, out_path = tempfile.mkstemp(suffix=".sig")
    os.close(out_fd)

    try:
        dsa.sign_file(in_path, out_path)
    except Exception as exc:
        os.remove(in_path)
        os.remove(out_path)
        raise HTTPException(status_code=500, detail=f"Помилка при підписанні: {exc}") from exc

    background_tasks.add_task(os.remove, in_path)
    return stream_file(out_path, background_tasks, f"{data_file.filename}.sig")


@app.post("/api/lab5/verify-file", responses={400: {"description": "Недійсний публічний ключ або помилка перевірки"}})
async def dsa_verify_file(
    background_tasks: BackgroundTasks,
    key_file: Annotated[UploadFile, File(...)],
    data_file: Annotated[UploadFile, File(...)],
    sig_file: Annotated[UploadFile, File(...)],
):
    dsa = DSA()
    load_key(dsa, "load_public_key",  await key_file.read(), LABEL_PUBLIC_KEY)

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as tmp_data:
        await tmp_data.write(await data_file.read())
        data_path = tmp_data.name

    async with aiofiles.tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as tmp_sig:
        await tmp_sig.write(await sig_file.read())
        sig_path = tmp_sig.name

    try:
        result = dsa.verify_file(data_path, sig_path)
    except Exception as exc:
        os.remove(data_path)
        os.remove(sig_path)
        raise HTTPException(status_code=400, detail=f"Помилка при перевірці: {exc}") from exc

    background_tasks.add_task(os.remove, data_path)
    background_tasks.add_task(os.remove, sig_path)
    return {"valid": result}