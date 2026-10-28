"use strict";

const passwordInput = document.querySelector("#password-input");
const toggleVisibilityButton = document.querySelector("#toggle-visibility");
const generateButton = document.querySelector("#generate-button");
const hashButton = document.querySelector("#hash-button");
const hashResult = document.querySelector("#hash-result");
const strengthRating = document.querySelector("#strength-rating");
const strengthSummary = document.querySelector("#strength-summary");
const entropyEstimate = document.querySelector("#entropy-estimate");
const strengthMeter = document.querySelector("#strength-meter");
const suggestionList = document.querySelector("#suggestion-list");
const meterSegments = [...document.querySelectorAll(".meter-segment")];
let hashRequestVersion = 0;

const commonPasswords = new Set([
  "123456", "123456789", "12345678", "1234567890", "1234567", "12345",
  "password", "password1", "password123", "passw0rd", "qwerty", "qwerty123",
  "qwertyuiop", "abc123", "111111", "123123", "000000", "iloveyou",
  "admin", "welcome", "letmein", "monkey", "dragon", "football",
  "baseball", "master", "login", "princess", "sunshine", "trustno1",
]);
const commonSequences = [
  "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz",
];
const ratings = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
const ratingColors = ["#ff7379", "#ff9d67", "#f0ca6c", "#88dba9", "#73e0be"];

function isCommonPassword(password) {
  const normalized = password.toLowerCase().replace(/[\s._-]/g, "");
  if (commonPasswords.has(normalized)) return true;
  if (/^(.)\1+$/.test(normalized)) return true;
  return commonSequences.some((sequence) => sequence.includes(normalized) && normalized.length >= 4);
}

function hasPredictablePattern(password) {
  const lower = password.toLowerCase();
  return /(.)\1{2,}/.test(password)
    || commonSequences.some((sequence) => {
      for (let start = 0; start <= sequence.length - 4; start += 1) {
        if (lower.includes(sequence.slice(start, start + 4))) return true;
      }
      return false;
    })
    || /(?:19|20)\d{2}/.test(password)
    || /(?:password|qwerty|letmein|welcome|admin)/i.test(password);
}

function getCharacterPoolSize(password) {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/\d/.test(password)) poolSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) poolSize += 33;
  return poolSize;
}

function updateChecks(password) {
  const checks = {
    length: password.length >= 12,
    variety: [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length >= 3,
    predictability: password.length > 0 && !hasPredictablePattern(password),
    uniqueness: password.length > 0 && !isCommonPassword(password),
  };
  document.querySelectorAll(".check-item").forEach((item) => {
    const passed = checks[item.dataset.check];
    item.classList.toggle("is-pass", passed);
    item.querySelector(".check-icon").textContent = passed ? "✓" : "○";
  });
  return checks;
}

function getSuggestions(password, checks) {
  if (!password) {
    return [
      "Use 12 or more characters; a longer passphrase is even better.",
      "Avoid names, dates, repeated characters, and familiar sequences.",
      "Use a unique password for every account.",
    ];
  }
  if (isCommonPassword(password)) {
    return [
      "This matches a commonly used password. Replace it with something completely different.",
      "Try a longer, unrelated passphrase instead of adding a number to a familiar word.",
      "Never reuse a password across accounts.",
    ];
  }
  const suggestions = [];
  if (!checks.length) suggestions.push("Add more length: aim for at least 12 characters, or use a longer passphrase.");
  if (!checks.variety) suggestions.push("Mix at least three character types, or choose several unrelated words.");
  if (!checks.predictability) suggestions.push("Remove repeated characters, keyboard runs, dates, and familiar password words.");
  if (checks.length && checks.variety && checks.predictability) {
    suggestions.push("Good foundation. Add a few more random characters to make guessing harder.");
  }
  suggestions.push("Make this password unique to one account; a password manager can help.");
  return suggestions.slice(0, 3);
}

function renderSuggestions(suggestions) {
  suggestionList.replaceChildren();
  suggestions.forEach((suggestion) => {
    const item = document.createElement("li");
    item.textContent = suggestion;
    if (suggestion.startsWith("Good foundation.")) item.classList.add("is-positive");
    suggestionList.append(item);
  });
}

function evaluatePassword(password) {
  const checks = updateChecks(password);
  if (!password) {
    strengthRating.textContent = "Waiting for input";
    strengthRating.style.color = "";
    strengthSummary.textContent = "Start typing to see your results";
    entropyEstimate.textContent = "—";
    strengthMeter.setAttribute("aria-valuenow", "0");
    meterSegments.forEach((segment) => { segment.style.background = ""; });
    renderSuggestions(getSuggestions("", checks));
    hashButton.disabled = true;
    return;
  }

  const common = isCommonPassword(password);
  const predictable = hasPredictablePattern(password);
  const poolSize = getCharacterPoolSize(password);
  const estimatedBits = Math.floor(password.length * Math.log2(Math.max(poolSize, 1)));
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 1;
  if (common) score = 0;
  else if (predictable) score = Math.max(0, score - 2);

  strengthRating.textContent = ratings[score];
  strengthRating.style.color = ratingColors[score];
  strengthSummary.textContent = common
    ? "This password is widely known and easy to guess"
    : predictable
      ? "A predictable pattern makes this easier to guess"
      : score >= 3
        ? "Nice work — this is harder to guess"
        : "A few changes could make this harder to guess";
  entropyEstimate.textContent = `~${estimatedBits} bits · rough estimate`;
  strengthMeter.setAttribute("aria-valuenow", String(score));
  meterSegments.forEach((segment, index) => {
    segment.style.background = index < score ? ratingColors[score] : "";
  });
  renderSuggestions(getSuggestions(password, checks));
  hashButton.disabled = false;
}

function randomIndex(maximum) {
  const limit = Math.floor(256 / maximum) * maximum;
  const byte = new Uint8Array(1);
  do {
    crypto.getRandomValues(byte);
  } while (byte[0] >= limit);
  return byte[0] % maximum;
}

function randomPassword() {
  const characterSets = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%^&*()-_=+",
  ];
  const alphabet = characterSets.join("");

  while (true) {
    const characters = characterSets.map((set) => set[randomIndex(set.length)]);
    while (characters.length < 20) {
      characters.push(alphabet[randomIndex(alphabet.length)]);
    }
    for (let index = characters.length - 1; index > 0; index -= 1) {
      const swapIndex = randomIndex(index + 1);
      [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
    }
    const password = characters.join("");
    if (!hasPredictablePattern(password)) return password;
  }
}

function resetHashResult() {
  hashResult.replaceChildren();
  const placeholder = document.createElement("div");
  placeholder.className = "hash-placeholder";
  const icon = document.createElement("span");
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "⌁";
  placeholder.append(icon, document.createTextNode(" Your hash will appear here"));
  hashResult.append(placeholder);
}

function showHashError(message) {
  hashResult.replaceChildren();
  const error = document.createElement("p");
  error.className = "hash-error";
  error.textContent = message;
  hashResult.append(error);
}

passwordInput.addEventListener("input", () => {
  hashRequestVersion += 1;
  hashButton.innerHTML = 'Hash this password <span aria-hidden="true">→</span>';
  evaluatePassword(passwordInput.value);
  resetHashResult();
});

toggleVisibilityButton.addEventListener("click", () => {
  const showing = passwordInput.type === "password";
  passwordInput.type = showing ? "text" : "password";
  toggleVisibilityButton.setAttribute("aria-pressed", String(showing));
  toggleVisibilityButton.setAttribute("aria-label", showing ? "Hide password" : "Show password");
});

generateButton.addEventListener("click", () => {
  hashRequestVersion += 1;
  hashButton.innerHTML = 'Hash this password <span aria-hidden="true">→</span>';
  passwordInput.value = randomPassword();
  evaluatePassword(passwordInput.value);
  resetHashResult();
  passwordInput.focus();
});

hashButton.addEventListener("click", async () => {
  const password = passwordInput.value;
  if (!password) return;
  const requestVersion = ++hashRequestVersion;
  hashButton.disabled = true;
  hashButton.textContent = "Creating hash…";
  hashResult.replaceChildren();
  const loadingMessage = document.createElement("div");
  loadingMessage.className = "hash-placeholder";
  loadingMessage.textContent = "Hashing locally on your Python server…";
  hashResult.append(loadingMessage);
  try {
    const response = await fetch("/api/hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The server could not create the hash.");
    if (requestVersion !== hashRequestVersion) return;

    hashResult.replaceChildren();
    for (const [label, value] of [
      ["SALT · RANDOM EACH TIME", result.salt],
      ["DERIVED HASH · HEX", result.hash],
    ]) {
      const outputLabel = document.createElement("p");
      outputLabel.className = "hash-output-label";
      outputLabel.textContent = label;
      const outputValue = document.createElement("p");
      outputValue.className = "hash-output-value";
      outputValue.textContent = value;
      hashResult.append(outputLabel, outputValue);
    }
  } catch (error) {
    if (requestVersion !== hashRequestVersion) return;
    showHashError(error instanceof TypeError
      ? "Could not reach the local Python server. Start it with python server.py and try again."
      : error.message);
  } finally {
    if (requestVersion === hashRequestVersion) {
      hashButton.disabled = passwordInput.value.length === 0;
      hashButton.innerHTML = 'Hash this password <span aria-hidden="true">→</span>';
    }
  }
});

evaluatePassword("");