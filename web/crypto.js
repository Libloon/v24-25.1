// start: Klientside-kryptering av kommentar før innsending - oppfyller F1 (privat kommentar) og NF7 (kryptering og nøkkelhåndtering i klient) (person 3)
const form = document.querySelector("#bidrag-form");

if (form) {
  const emailField = document.querySelector("#epost");
  const passwordField = document.querySelector("#passord");
  const titleField = document.querySelector("#tittel");
  const commentField = document.querySelector("#kommentar");
  const textField = document.querySelector("#tekst");
  const metadataField = document.querySelector("#offentlig_nokkel");
  const responseField = document.querySelector("#respons-felt");
  const submitButtons = Array.from(document.querySelectorAll(".buttons input[type='submit']"));
  // start: HTTPS-kall med fallback til TLS-gateway nar frontend er apnet pa gammel port i steg 9 - oppfyller NF7 (TLS/HTTPS) og F1 (sikker brukerflyt) (person 4 og person 5)
  function resolveGatewayOrigin() {
    if (window.location.protocol === "https:" && window.location.port === "8443") {
      return window.location.origin;
    }

    if (window.location.hostname === "127.0.0.1") {
      return "https://127.0.0.1:8443";
    }

    return "https://localhost:8443";
  }

  const formAction = new URL(form.getAttribute("action") || "/cgi-bin/index.cgi", resolveGatewayOrigin()).toString();
  form.setAttribute("action", formAction);
  // slutt: HTTPS-kall med fallback til TLS-gateway nar frontend er apnet pa gammel port i steg 9 - oppfyller NF7 (TLS/HTTPS) og F1 (sikker brukerflyt) (person 4 og person 5)

  const ACTIONS_WITH_ENCRYPTION = new Set(["Ny", "Endre"]);
  const ACTIONS_WITH_FETCH = new Set(["Ny", "Endre", "Slett", "Liste", "Min", "Admin"]);
  const PBKDF2_ITERATIONS = 150000;
  const MAX_COMMENT_BYTES = 700;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function findSubmitter(event) {
    if (event.submitter) {
      return event.submitter;
    }

    if (document.activeElement instanceof HTMLInputElement && document.activeElement.type === "submit") {
      return document.activeElement;
    }

    return null;
  }

  function bytesToBase64(bytes) {
    let binary = "";

    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });

    return btoa(binary);
  }

  // start: Steg 7-klientflyt for skjult ciphertext og egen visning - oppfyller F1 (privat kommentar for bruker) og NF1 (sikker håndtering av ciphertext i flyten) (person 5)
  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  }

  function setBusyState(isBusy) {
    submitButtons.forEach((button) => {
      button.disabled = isBusy;
    });
  }

  function setMessage(element, message, type) {
    if (!element) {
      return;
    }

    element.textContent = message;
    element.hidden = !message;
    element.dataset.state = type;
  }

  function showResponse(message, type) {
    setMessage(responseField, message, type);
  }

  function showNamedResponse(title, message, type) {
    const content = message ? `${title}\n\n${message}` : title;
    showResponse(content, type);
  }

  function clearFeedback() {
    showResponse("", "info");
  }

  function hasContributionContent(response) {
    return Boolean(
      response.tittel.trim()
      || response.tekst.trim()
      || response.kommentar.trim()
    );
  }

  function classifyMessage(message) {
    if (!message) {
      return "info";
    }

    return /(feil|mangler|ingen tilgang|ukjent|kunne ikke|støtter ikke|ugyldig)/i.test(message)
      ? "error"
      : "success";
  }

  async function deriveCommentKey(email, password, salt, iterations, usages) {
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      encoder.encode(`${email}\n${password}`),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      usages
    );
  }

  async function encryptComment(comment, email, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveCommentKey(email, password, salt, PBKDF2_ITERATIONS, ["encrypt"]);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      encoder.encode(comment)
    );

    return {
      ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
      metadata: `enc-v1|${PBKDF2_ITERATIONS}|${bytesToBase64(salt)}|${bytesToBase64(iv)}`
    };
  }

  function parseMetadata(metadata) {
    const parts = metadata.split("|");

    if (parts.length !== 4 || parts[0] !== "enc-v1") {
      throw new Error("Ugyldig krypteringsmetadata.");
    }

    const iterations = Number(parts[1]);

    if (!Number.isFinite(iterations) || iterations < 1) {
      throw new Error("Ugyldig antall iterasjoner i krypteringsmetadata.");
    }

    return {
      iterations,
      salt: base64ToBytes(parts[2]),
      iv: base64ToBytes(parts[3])
    };
  }

  async function decryptComment(ciphertext, metadata, email, password) {
    const parsedMetadata = parseMetadata(metadata);
    const key = await deriveCommentKey(
      email,
      password,
      parsedMetadata.salt,
      parsedMetadata.iterations,
      ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: parsedMetadata.iv
      },
      key,
      base64ToBytes(ciphertext)
    );

    return decoder.decode(decryptedBuffer);
  }

  function buildRequestBody(action, commentValue, metadataValue) {
    const params = new URLSearchParams();

    params.set("epost", emailField.value.trim());
    params.set("passord", passwordField.value);
    params.set("tittel", titleField.value);
    params.set("kommentar", commentValue);
    params.set("offentlig_nokkel", metadataValue);
    params.set("tekst", textField.value);
    params.set("handling", action);

    return params;
  }

  async function submitAction(action, commentValue, metadataValue) {
    const response = await fetch(formAction, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
      },
      body: buildRequestBody(action, commentValue, metadataValue).toString()
    });

    return response.text();
  }

  function parseMinResponse(responseText) {
    const trimmed = responseText.trim();

    if (!trimmed.startsWith("<min>")) {
      return null;
    }

    const xmlDocument = new DOMParser().parseFromString(trimmed, "application/xml");

    if (xmlDocument.querySelector("parsererror")) {
      return null;
    }

    const root = xmlDocument.querySelector("min");

    if (!root) {
      return null;
    }

    const readField = (fieldName) => root.querySelector(fieldName)?.textContent ?? "";

    return {
      tittel: readField("tittel"),
      tekst: readField("tekst"),
      kommentar: readField("kommentar"),
      offentligNokkel: readField("offentlig_nokkel")
    };
  }

  function clearContributionFields() {
    titleField.value = "";
    commentField.value = "";
    textField.value = "";
    metadataField.value = "";
  }

  async function handleEncryptedWrite(action) {
    const comment = commentField.value;
    let commentToSend = comment;
    let metadataToSend = "";

    if (comment.trim()) {
      if (!window.crypto || !window.crypto.subtle) {
        throw new Error("Nettleseren støtter ikke klientside-kryptering av kommentar.");
      }

      const email = emailField.value.trim();
      const password = passwordField.value;
      const commentBytes = encoder.encode(comment);

      if (!email || !password) {
        throw new Error("E-post og passord må fylles ut før kommentar kan krypteres.");
      }

      if (commentBytes.length > MAX_COMMENT_BYTES) {
        throw new Error("Kommentar er for lang til å krypteres trygt i dagens lagringsfelt.");
      }

      const encryptedComment = await encryptComment(comment, email, password);

      commentToSend = encryptedComment.ciphertext;
      metadataToSend = encryptedComment.metadata;
    }

    const responseText = await submitAction(action, commentToSend, metadataToSend);
    const responseType = classifyMessage(responseText);

    metadataField.value = "";
    showNamedResponse(action, responseText || "Ingen respons fra backend.", responseType);

    if (responseType === "success") {
      const listeText = await submitAction("Liste", "", "");
      showNamedResponse(action + " → Liste", listeText || "Ingen bidrag å vise.", "success");
    }
  }

  async function handleDelete() {
    const action = "Slett";
    const responseText = await submitAction(action, commentField.value, "");
    const responseType = classifyMessage(responseText);

    showNamedResponse(action, responseText || "Ingen respons fra backend.", responseType);

    if (responseType === "success") {
      clearContributionFields();
    }
  }

  async function handleMinView() {
    const responseText = await submitAction("Min", commentField.value, metadataField.value);
    const parsedResponse = parseMinResponse(responseText);

    if (!parsedResponse) {
      showNamedResponse("Min", responseText || "Ingen data funnet for brukeren.", classifyMessage(responseText));
      return;
    }

    if (!hasContributionContent(parsedResponse)) {
      showNamedResponse("Min", "Ingen data funnet for brukeren.", "info");
      return;
    }

    let resolvedComment = parsedResponse.kommentar;

    if (parsedResponse.kommentar && parsedResponse.offentligNokkel) {
      try {
        resolvedComment = await decryptComment(
          parsedResponse.kommentar,
          parsedResponse.offentligNokkel,
          emailField.value.trim(),
          passwordField.value
        );
      } catch (error) {
        showNamedResponse("Min", "Kommentar ble hentet, men kunne ikke dekrypteres. Kontroller at du bruker riktig e-post og passord.", "error");
        return;
      }
    }

    showNamedResponse(
      "Min",
      `tittel = ${parsedResponse.tittel}\nkommentar = ${resolvedComment}\ntekst = ${parsedResponse.tekst}`,
      "success"
    );
  }

  async function handleReadOnlyResponse(action) {
    const responseText = await submitAction(action, commentField.value, metadataField.value);
    const responseType = classifyMessage(responseText);

    showNamedResponse(action, responseText || "Ingen respons fra backend.", responseType);
  }
  // slutt: Steg 7-klientflyt for skjult ciphertext og egen visning - oppfyller F1 (privat kommentar for bruker) og NF1 (sikker håndtering av ciphertext i flyten) (person 5)

  form.addEventListener("submit", async (event) => {
    const submitter = findSubmitter(event);
    const action = submitter?.value ?? "";

    if (!ACTIONS_WITH_FETCH.has(action)) {
      return;
    }

    event.preventDefault();
    clearFeedback();
    setBusyState(true);

    try {
      if (action === "Min") {
        await handleMinView();
      } else if (action === "Liste" || action === "Admin") {
        await handleReadOnlyResponse(action);
      } else if (action === "Slett") {
        await handleDelete();
      } else if (ACTIONS_WITH_ENCRYPTION.has(action)) {
        await handleEncryptedWrite(action);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Ukjent feil i steg 7-flyten.";
      showNamedResponse(action || "Respons", message, "error");
    } finally {
      setBusyState(false);
    }
  });
}
// slutt: Klientside-kryptering av kommentar før innsending - oppfyller F1 (privat kommentar) og NF7 (kryptering og nøkkelhåndtering i klient) (person 3)

