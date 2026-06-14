(function () {
  const META_URL = './payload.meta.json';
  const PAYLOAD_URL = './payload.enc';
  const PAYLOAD_FORMAT = 'sg10.encrypted.pages.payload.v1';

  const form = document.getElementById('unlock-form');
  const passwordInput = document.getElementById('unlock-password');
  const submitButton = document.getElementById('unlock-submit');
  const statusNode = document.getElementById('unlock-status');
  const progressNode = document.getElementById('unlock-progress');
  const progressBar = document.getElementById('unlock-progressbar');
  const progressFill = document.getElementById('unlock-progress-fill');
  const progressLabel = document.getElementById('unlock-progress-label');
  const progressPercent = document.getElementById('unlock-progress-percent');

  function setStatus(message, isError) {
    statusNode.textContent = message;
    statusNode.classList.toggle('is-error', Boolean(isError));
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function setProgress(value, label) {
    const progress = Math.round(clamp(value, 0, 100));
    progressNode.hidden = false;
    progressNode.classList.remove('is-error');
    progressFill.style.width = `${progress}%`;
    progressBar.setAttribute('aria-valuenow', String(progress));
    progressLabel.textContent = label;
    progressPercent.textContent = `${progress}%`;
  }

  function resetProgress() {
    progressNode.hidden = true;
    progressNode.classList.remove('is-error');
    progressFill.style.width = '0%';
    progressBar.setAttribute('aria-valuenow', '0');
    progressLabel.textContent = '准备解锁...';
    progressPercent.textContent = '0%';
  }

  function markProgressError(label) {
    progressNode.hidden = false;
    progressNode.classList.add('is-error');
    progressLabel.textContent = label;
  }

  function nextFrame() {
    return new Promise((resolve) => {
      requestAnimationFrame(() => resolve());
    });
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }

  async function runWithSoftProgress(task, startProgress, endProgress, label) {
    let currentProgress = startProgress;
    setProgress(currentProgress, label);
    await nextFrame();

    const timer = setInterval(() => {
      currentProgress += Math.max(0.3, (endProgress - currentProgress) * 0.08);
      setProgress(Math.min(endProgress - 1, currentProgress), label);
    }, 240);

    try {
      return await task();
    } finally {
      clearInterval(timer);
      setProgress(endProgress, label);
    }
  }

  function bytesFromBase64(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function authenticatedMetadata(meta) {
    return JSON.stringify({
      version: meta.version,
      format: meta.format,
      algorithm: meta.algorithm,
      kdf: meta.kdf,
      hash: meta.hash,
      keyBits: meta.keyBits,
      iterations: meta.iterations,
      payload: meta.payload,
    });
  }

  async function deriveAesKey(password, meta) {
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: bytesFromBase64(meta.salt),
        iterations: meta.iterations,
        hash: meta.hash,
      },
      passwordKey,
      { name: 'AES-GCM', length: meta.keyBits },
      false,
      ['decrypt'],
    );
  }

  async function readPayloadBytes(response, startProgress, endProgress) {
    const totalBytes = Number(response.headers.get('content-length')) || 0;

    if (!response.body) {
      const buffer = await response.arrayBuffer();
      setProgress(endProgress, `加密包下载完成 ${formatBytes(buffer.byteLength)}`);
      return buffer;
    }

    const reader = response.body.getReader();
    const chunks = [];
    let receivedBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      chunks.push(value);
      receivedBytes += value.byteLength;

      if (totalBytes > 0) {
        const ratio = receivedBytes / totalBytes;
        setProgress(
          startProgress + ratio * (endProgress - startProgress),
          `正在下载加密包 ${formatBytes(receivedBytes)} / ${formatBytes(totalBytes)}`,
        );
      } else {
        setProgress(
          Math.min(endProgress - 1, startProgress + chunks.length),
          `正在下载加密包 ${formatBytes(receivedBytes)}`,
        );
      }

      await nextFrame();
    }

    const bytes = new Uint8Array(receivedBytes);
    let offset = 0;
    chunks.forEach((chunk) => {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    });

    setProgress(endProgress, `加密包下载完成 ${formatBytes(receivedBytes)}`);
    return bytes.buffer;
  }

  async function decryptPayload(password) {
    setProgress(5, '正在读取发布信息...');
    const metaResponse = await fetch(META_URL, { cache: 'no-store' });

    if (!metaResponse.ok) {
      throw new Error('release_files_missing');
    }

    const meta = await metaResponse.json();
    if (meta.format !== 'sg10.encrypted.pages.v1' || meta.payload !== 'payload.enc') {
      throw new Error('release_metadata_invalid');
    }

    setProgress(15, '正在请求加密包...');
    const payloadResponse = await fetch(PAYLOAD_URL, { cache: 'no-store' });
    if (!payloadResponse.ok) {
      throw new Error('release_files_missing');
    }

    const encryptedBytes = await readPayloadBytes(payloadResponse, 18, 52);
    const key = await runWithSoftProgress(
      () => deriveAesKey(password, meta),
      60,
      74,
      '正在派生解密密钥...',
    );

    const plainBuffer = await runWithSoftProgress(
      () => crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bytesFromBase64(meta.iv),
          additionalData: new TextEncoder().encode(authenticatedMetadata(meta)),
        },
        key,
        encryptedBytes,
      ),
      76,
      86,
      '正在解密内容...',
    );

    setProgress(88, '正在解析页面...');
    await nextFrame();
    return JSON.parse(new TextDecoder().decode(plainBuffer));
  }

  function runScript(code, sourceName) {
    const script = document.createElement('script');
    script.textContent = `${code}\n//# sourceURL=${sourceName}`;
    document.head.appendChild(script);
    script.remove();
  }

  function mountPayload(payload) {
    if (!payload || payload.format !== PAYLOAD_FORMAT) {
      throw new Error('payload_invalid');
    }

    document.title = payload.title || document.title;
    document.documentElement.lang = payload.lang || 'zh-CN';
    document.head.querySelectorAll('[data-encrypted-pages-runtime]').forEach((node) => node.remove());

    const style = document.createElement('style');
    style.dataset.encryptedPagesRuntime = 'true';
    style.textContent = payload.css || '';
    document.head.appendChild(style);

    document.body.innerHTML = payload.bodyHtml;
    runScript(payload.dataScript, 'sg10-data-runtime.js');
    runScript(payload.appScript, 'sg10-ui-runtime.js');
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const password = passwordInput.value.trim();
    if (!password) {
      setStatus('请输入发布密码。', true);
      passwordInput.focus();
      return;
    }

    submitButton.disabled = true;
    passwordInput.disabled = true;
    resetProgress();
    setProgress(2, '准备解锁...');
    setStatus('正在解密并启动...', false);

    try {
      const payload = await decryptPayload(password);
      setProgress(94, '正在装载页面...');
      await nextFrame();
      setProgress(100, '启动完成');
      await new Promise((resolve) => {
        setTimeout(resolve, 120);
      });
      mountPayload(payload);
    } catch (error) {
      console.error(error);
      passwordInput.disabled = false;
      submitButton.disabled = false;
      passwordInput.select();
      markProgressError('解锁失败');
      setStatus('解锁失败。请确认密码没有输错；如果刚更新过页面，请强制刷新后重试。', true);
    }
  });
}());
