export type PasswordStrengthResult = {
  ok: boolean;
  score: number;
  reasons: string[];
};

const MIN_LENGTH = 8;
const RECOMMENDED_LENGTH = 12;

export function checkPasswordStrength(password: string): PasswordStrengthResult {
  const reasons: string[] = [];
  let score = 0;

  if (password.length < MIN_LENGTH) {
    reasons.push(`too short (${password.length} chars, minimum ${MIN_LENGTH})`);
  } else {
    score += 1;
    if (password.length >= RECOMMENDED_LENGTH) {
      score += 1;
    } else {
      reasons.push(`consider using at least ${RECOMMENDED_LENGTH} characters`);
    }
  }

  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) {
    score += 1;
  } else {
    reasons.push("missing mixed case (upper + lower)");
  }

  if (/\d/.test(password)) {
    score += 1;
  } else {
    reasons.push("missing digits");
  }

  if (/[^a-zA-Z0-9]/.test(password)) {
    score += 1;
  } else {
    reasons.push("missing special characters");
  }

  return {
    ok: password.length >= MIN_LENGTH,
    score,
    reasons,
  };
}
