async function runLab1() {
    document.getElementById('loader').style.display = 'block';
    const payload = {
        m:  Number.parseInt(document.getElementById('m').value),
        a:  Number.parseInt(document.getElementById('a').value),
        c:  Number.parseInt(document.getElementById('c').value),
        x0: Number.parseInt(document.getElementById('x0').value),
        n:  Number.parseInt(document.getElementById('n').value)
    };

    try {
        const res = await fetch('/api/lab1/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        document.getElementById('my-pi').innerText = data.my_pi;
        document.getElementById('rand-pi').innerText = data.rand_pi;

        let seq = data.preview.join(', ');
        if (data.total > data.preview.length)
            seq += `\n\n... (Показано ${data.preview.length} з ${data.total})`;
        document.getElementById('res-box').innerText = seq;
    } catch (e) {
        alert("Помилка: " + e.message);
    } finally {
        document.getElementById('loader').style.display = 'none';
    }
}