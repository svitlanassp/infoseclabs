let lastResult = { target: "", hash: "", type: "" };

function readHashFile(input) {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (e) {
        const content = e.target.result.trim();
        const hash = content.split(/\s+/)[0];
        document.getElementById('expected-hash').value = hash;
    };
    reader.readAsText(file);
}

async function hashString() {
    const text = document.getElementById('str-input').value;
    const formData = new FormData();
    formData.append('text', text);

    try {
        const res = await fetch('/api/lab2/hash-string', { method: 'POST', body: formData });
        const data = await res.json();
        document.getElementById('str-res').innerText = data.hash;
        document.getElementById('save-str-btn').style.display = 'block';
        lastResult = {
            target: text === "" ? "[Empty String]" : text,
            hash: data.hash,
            type: "String Text Hashing"
        };
    } catch (e) {
        console.error("Виникла помилка під час запиту:", e);
        alert("Помилка сервера");
    }
}

async function processFile() {
    const fileInput = document.getElementById('file-input');
    const expected = document.getElementById('expected-hash').value.trim();
    if (fileInput.files.length === 0) return alert("Оберіть основний файл!");

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    document.getElementById('file-loader').style.display = 'block';
    document.getElementById('save-file-btn').style.display = 'none';
    document.getElementById('file-res').style.color = "#a78bfa";

    try {
        if (expected) {
            formData.append('expected', expected);
            const res = await fetch('/api/lab2/verify-file', { method: 'POST', body: formData });
            const data = await res.json();

            const status = data.is_ok ? "ЗБІГАЄТЬСЯ" : "НЕ ЗБІГАЄТЬСЯ";
            document.getElementById('file-res').style.color = data.is_ok ? "#34d399" : "#ef4444";
            document.getElementById('file-res').innerHTML =
                `Файл: ${data.filename}<br>` +
                `Очікуваний: ${expected}<br>` +
                `Фактичний: ${data.actual}<br>` +
                `Статус: <b>${status}</b>`;

            lastResult = { target: data.filename, hash: data.actual, type: "File Verification" };
        } else {
            const res = await fetch('/api/lab2/hash-file', { method: 'POST', body: formData });
            const data = await res.json();
            document.getElementById('file-res').innerHTML = `Файл: ${data.filename}<br>MD5: ${data.hash}`;
            lastResult = { target: data.filename, hash: data.hash, type: "File Hashing" };
        }
        document.getElementById('save-file-btn').style.display = 'block';
    } catch (e) {
        console.error("Виникла помилка під час запиту:", e);
        alert("Помилка обробки");
    } finally {
        document.getElementById('file-loader').style.display = 'none';
    }
}

async function saveToFile(source) {
    const formData = new FormData();
    formData.append('target', lastResult.target);
    formData.append('result', lastResult.hash);
    formData.append('type', lastResult.type);

    const response = await fetch('/api/lab2/download-report', { method: 'POST', body: formData });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "md5_report.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
}
