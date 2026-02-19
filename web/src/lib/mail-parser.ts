export interface ParsedMail {
  headers: Record<string, string>;
  html?: string;
  text?: string;
}

export function parseRawMail(raw: string): ParsedMail {
  // Use a more robust split for header/body separation
  const headerEndIndex = raw.search(/\r?\n\r?\n/);
  if (headerEndIndex === -1) {
    return { headers: parseHeaders(raw), text: "" };
  }

  const headerSection = raw.slice(0, headerEndIndex);
  const bodySection = raw.slice(headerEndIndex).trim();

  const headers = parseHeaders(headerSection);
  const contentType = (headers["content-type"] || "text/plain").toLowerCase();

  if (contentType.includes("multipart/")) {
    const boundaryMatch = contentType.match(/boundary="?([^";\s]+)"?/i);
    if (boundaryMatch) {
      const boundary = boundaryMatch[1];
      const result: ParsedMail = { headers, html: "", text: "" };
      const mimeParts = bodySection.split(`--${boundary}`);

      for (const part of mimeParts) {
        const trimmedPart = part.trim();
        if (!trimmedPart || trimmedPart === "--") continue;

        const subParsed = parseRawMail(trimmedPart);
        if (subParsed.html) result.html += subParsed.html;
        if (subParsed.text) result.text += subParsed.text;
      }
      return result;
    }
  }

  if (contentType.includes("text/html")) {
    return { headers, html: bodySection };
  }

  return { headers, text: bodySection };
}

function parseHeaders(raw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = raw.split(/\r?\n/);
  let currentKey = "";

  for (const line of lines) {
    if (line.match(/^\s/) && currentKey) {
      headers[currentKey] += " " + line.trim();
    } else {
      const colonIndex = line.indexOf(":");
      if (colonIndex !== -1) {
        currentKey = line.slice(0, colonIndex).toLowerCase().trim();
        headers[currentKey] = line.slice(colonIndex + 1).trim();
      }
    }
  }

  return headers;
}
