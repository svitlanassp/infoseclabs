async function generateKeys() {
    const status = document.getElementById('status-gen');
    status.innerText = "Генерація ключів...";

    try {
        const response = await fetch('/api/lab4/generate-keys', { method: 'POST' });
        const data = await response.json();

        const time = new Date().toLocaleTimeString('uk-UA').replaceAll(':', '-');

        const downloadFile = (name, base64Content) => {
            const link = document.createElement('a');
            link.href = 'data:application/x-pem-file;base64,' + base64Content;
            link.download = name.replace('.pem', `_${time}.pem`);
            link.click();
        };

        downloadFile('private_key.pem', data.private);
        downloadFile('public_key.pem', data.public);

        status.innerText = `✅ Ключі збережено як private_key_${time}.pem та public_key_${time}.pem`;
    } catch (e) {
        console.error("Виникла помилка:", e);
        status.innerText = "❌ Помилка при генерації.";
    }
}

async function process(mode) {
    const isEnc = mode === 'encrypt';
    const prefix = isEnc ? 'enc' : 'dec';

    const keyInput  = document.getElementById(`${prefix}-key-file`);
    const dataInput = document.getElementById(`${prefix}-data-file`);
    const status    = document.getElementById(`status-${prefix}`);

    status.className = "status";

    if (keyInput.files.length === 0 || dataInput.files.length === 0) {
        status.innerText = "❌ Будь ласка, оберіть файл ключа та файл даних!";
        status.className = "status error-text";
        return;
    }

    const formData = new FormData();
    formData.append('key_file', keyInput.files[0]);
    formData.append('data_file', dataInput.files[0]);

    status.innerText = "Обробка... зачекайте";

    try {
        const response = await fetch(`/api/lab4/${mode}`, { method: 'POST', body: formData });

        const contentType = response.headers.get("content-type");
        if (contentType?.includes("application/json")) {
            const err = await response.json();
            status.innerText = `❌ ${err.error}`;
            status.className = "status error-text";
            return;
        }

        if (response.ok) {
            const blob = await response.blob();
            const url = globalThis.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;

            let filename = dataInput.files[0].name;
            a.download = isEnc
                ? filename + ".enc"
                : (filename.endsWith('.enc') ? filename.replace('.enc', '') : 'decrypted_' + filename);
            a.click();
            status.innerText = "✅ Готово! Файл завантажено.";
        } else {
            status.innerText = "❌ Помилка сервера.";
            status.className = "status error-text";
        }
    } catch (e) {
        console.error("Виникла помилка ", e);
        status.innerText = "❌ З'єднання втрачено.";
        status.className = "status error-text";
    }
}
