let currentSignMode = 'text';
let currentVerifyMode = 'text';

function switchTab(action, mode) {
    if (action === 'sign') {
        currentSignMode = mode;
        document.getElementById('btn-sign-text').classList.toggle('active', mode === 'text');
        document.getElementById('btn-sign-file').classList.toggle('active', mode === 'file');
        document.getElementById('section-sign-text').classList.toggle('active', mode === 'text');
        document.getElementById('section-sign-file').classList.toggle('active', mode === 'file');
    } else {
        currentVerifyMode = mode;
        document.getElementById('btn-verify-text').classList.toggle('active', mode === 'text');
        document.getElementById('btn-verify-file').classList.toggle('active', mode === 'file');
        document.getElementById('section-verify-text').classList.toggle('active', mode === 'text');
        document.getElementById('section-verify-file').classList.toggle('active', mode === 'file');
    }
}

async function generateKeys() {
    const status = document.getElementById('status-gen');
    status.innerText = "Генерація ключів...";
    status.className = "status";

    try {
        const response = await fetch('/api/lab5/generate-keys', { method: 'POST' });
        const data = await response.json();

        const time = new Date().toLocaleTimeString('uk-UA').replace(/:/g, '-');

        const downloadFile = (name, base64Content) => {
            const link = document.createElement('a');
            link.href = 'data:application/x-pem-file;base64,' + base64Content;
            link.download = name.replace('.pem', `_${time}.pem`);
            link.click();
        };

        downloadFile('dsa_private_key.pem', data.private);
        downloadFile('dsa_public_key.pem', data.public);

        status.innerText = `✅ Ключі успішно збережено`;
        status.className = "status success-text";
    } catch (e) {
        status.innerText = "❌ Помилка при генерації ключів.";
        status.className = "status error-text";
    }
}

async function processSign() {
    const keyInput = document.getElementById('sign-key');
    const status = document.getElementById('status-sign');
    const formData = new FormData();

    if (keyInput.files.length === 0) {
        status.innerText = "❌ Оберіть приватний ключ";
        status.className = "status error-text";
        return;
    }
    formData.append('key_file', keyInput.files[0]);

    let endpoint = '';
    let fileName = '';

    if (currentSignMode === 'text') {
        const textInput = document.getElementById('sign-text-input');
        if (textInput.value.trim() === "") {
            status.innerText = "❌ Введіть текст для підпису";
            status.className = "status error-text";
            return;
        }
        formData.append('text', textInput.value);
        endpoint = '/api/lab5/sign-text';
        fileName = 'text_signature.sig';
    } else {
        const fileInput = document.getElementById('sign-file-input');
        if (fileInput.files.length === 0) {
            status.innerText = "❌ Оберіть файл для підпису";
            status.className = "status error-text";
            return;
        }
        formData.append('data_file', fileInput.files[0]);
        endpoint = '/api/lab5/sign-file';
        fileName = fileInput.files[0].name + '.sig';
    }

    status.innerText = "Створення підпису...";
    status.className = "status";

    try {
        const response = await fetch(endpoint, { method: 'POST', body: formData });

        const contentType = response.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
            const data = await response.json();
            status.innerText = `❌ ${data.error}`;
            status.className = "status error-text";
            return;
        }

        if (response.ok) {
            const hexSignature = await response.text();

            const blob = new Blob([hexSignature], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = fileName;
            a.click();

            status.innerHTML = `✅ <b>Підпис збережено як ${fileName}</b><br><br><b>Підпис (Hex):</b><br><textarea rows="3" readonly style="margin-top:5px; width:100%;">${hexSignature}</textarea>`;
            status.className = "status success-text";
        }
    } catch (e) {
        status.innerText = "❌ Помилка з'єднання.";
        status.className = "status error-text";
    }
}

async function processVerify() {
    const keyInput = document.getElementById('verify-key');
    const sigInput = document.getElementById('verify-sig-input');
    const status = document.getElementById('status-verify');
    const formData = new FormData();

    if (keyInput.files.length === 0 || sigInput.files.length === 0) {
        status.innerText = "❌ Завантажте публічний ключ та файл підпису (.sig)";
        status.className = "status error-text";
        return;
    }
    formData.append('key_file', keyInput.files[0]);
    formData.append('sig_file', sigInput.files[0]);

    let endpoint = '';

    if (currentVerifyMode === 'text') {
        const textInput = document.getElementById('verify-text-input');
        if (textInput.value.trim() === "") {
            status.innerText = "❌ Введіть оригінальний текст";
            status.className = "status error-text";
            return;
        }
        formData.append('text', textInput.value);
        endpoint = '/api/lab5/verify-text';
    } else {
        const fileInput = document.getElementById('verify-file-input');
        if (fileInput.files.length === 0) {
            status.innerText = "❌ Завантажте оригінальний файл";
            status.className = "status error-text";
            return;
        }
        formData.append('data_file', fileInput.files[0]);
        endpoint = '/api/lab5/verify-file';
    }

    status.innerText = "Перевірка...";
    status.className = "status";

    try {
        const response = await fetch(endpoint, { method: 'POST', body: formData });
        const data = await response.json();

        if (data.error) {
            status.innerText = `❌ ${data.error}`;
            status.className = "status error-text";
        } else if (data.valid) {
            status.innerText = "✅ Підпис дісний";
            status.className = "status success-text";
        } else {
            status.innerText = "❌ Підпис не дісний";
            status.className = "status error-text";
        }
    } catch (e) {
        status.innerText = "❌ Помилка при перевірці.";
        status.className = "status error-text";
    }
}