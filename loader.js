(function () {
  const META_URL = './payload.meta.json';
  const PAYLOAD_URL = './payload.enc';
  const PAYLOAD_FORMAT = 'sg10.encrypted.pages.payload.v1';

  const form = document.getElementById('unlock-form');
  const passwordInput = document.getElementById('unlock-password');
  const submitButton = document.getElementById('unlock-submit');
  const statusNode = document.getElementById('unlock-status');

  function setStatus(message, isError) {
    statusNode.textContent = message;
    statusNode.classList.toggle('is-error', Boolean(isError));
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

  async function decryptPayload(password) {
    const [metaResponse, payloadResponse] = await Promise.all([
      fetch(META_URL, { cache: 'no-store' }),
      fetch(PAYLOAD_URL, { cache: 'no-store' }),
    ]);

    if (!metaResponse.ok || !payloadResponse.ok) {
      throw new Error('release_files_missing');
    }

    const meta = await metaResponse.json();
    if (meta.format !== 'sg10.encrypted.pages.v1' || meta.payload !== 'payload.enc') {
      throw new Error('release_metadata_invalid');
    }

    const key = await deriveAesKey(password, meta);
    const encryptedBytes = await payloadResponse.arrayBuffer();
    const plainBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: bytesFromBase64(meta.iv),
        additionalData: new TextEncoder().encode(authenticatedMetadata(meta)),
      },
      key,
      encryptedBytes,
    );

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

    const password = passwordInput.value;
    if (!password) {
      setStatus('请输入发布密码。', true);
      passwordInput.focus();
      return;
    }

    submitButton.disabled = true;
    passwordInput.disabled = true;
    setStatus('正在解密并启动...', false);

    try {
      const payload = await decryptPayload(password);
      mountPayload(payload);
    } catch (error) {
      console.error(error);
      passwordInput.disabled = false;
      submitButton.disabled = false;
      passwordInput.select();
      setStatus('解锁失败。请检查密码或发布文件是否完整。', true);
    }
  });
}());
