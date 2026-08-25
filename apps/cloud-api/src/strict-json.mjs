export class DuplicateJsonKeyError extends SyntaxError {
  constructor(key) {
    super("duplicate JSON object key");
    this.name = "DuplicateJsonKeyError";
    // Do not attach the caller-controlled key to the public error object.
    void key;
  }
}

/** Parse JSON without the duplicate-key information loss of JSON.parse(). */
export function parseJsonNoDuplicateKeys(text) {
  if (typeof text !== "string" || text.length === 0) throw new SyntaxError("empty JSON");
  const parser = new JsonParser(text);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (parser.position !== parser.text.length) throw new SyntaxError("trailing JSON");
  return value;
}

class JsonParser {
  constructor(text) { this.text = text; this.position = 0; }
  parseValue() {
    this.skipWhitespace();
    const character = this.text[this.position];
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (this.text.startsWith("true", this.position)) { this.position += 4; return true; }
    if (this.text.startsWith("false", this.position)) { this.position += 5; return false; }
    if (this.text.startsWith("null", this.position)) { this.position += 4; return null; }
    return this.parseNumber();
  }
  parseObject() {
    this.position += 1;
    const result = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.text[this.position] === "}") { this.position += 1; return result; }
    while (true) {
      this.skipWhitespace();
      if (this.text[this.position] !== '"') throw new SyntaxError("object key expected");
      const key = this.parseString();
      if (keys.has(key)) throw new DuplicateJsonKeyError(key);
      keys.add(key);
      this.skipWhitespace();
      if (this.text[this.position] !== ":") throw new SyntaxError("colon expected");
      this.position += 1;
      result[key] = this.parseValue();
      this.skipWhitespace();
      const delimiter = this.text[this.position];
      this.position += 1;
      if (delimiter === "}") return result;
      if (delimiter !== ",") throw new SyntaxError("object delimiter expected");
    }
  }
  parseArray() {
    this.position += 1;
    const result = [];
    this.skipWhitespace();
    if (this.text[this.position] === "]") { this.position += 1; return result; }
    while (true) {
      result.push(this.parseValue());
      this.skipWhitespace();
      const delimiter = this.text[this.position];
      this.position += 1;
      if (delimiter === "]") return result;
      if (delimiter !== ",") throw new SyntaxError("array delimiter expected");
    }
  }
  parseString() {
    const start = this.position;
    this.position += 1;
    while (this.position < this.text.length) {
      const character = this.text[this.position];
      this.position += 1;
      if (character === "\\") {
        if (this.position >= this.text.length) throw new SyntaxError("invalid escape");
        this.position += 1;
        continue;
      }
      if (character === '"') {
        try { return JSON.parse(this.text.slice(start, this.position)); }
        catch { throw new SyntaxError("invalid string"); }
      }
      if (character < " ") throw new SyntaxError("control character in string");
    }
    throw new SyntaxError("unterminated string");
  }
  parseNumber() {
    const match = this.text.slice(this.position).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (!match) throw new SyntaxError("value expected");
    this.position += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new SyntaxError("number is invalid");
    return number;
  }
  skipWhitespace() {
    while (/[\u0020\u0009\u000a\u000d]/u.test(this.text[this.position] ?? "")) this.position += 1;
  }
}
