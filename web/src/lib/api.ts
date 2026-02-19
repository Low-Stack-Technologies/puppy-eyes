export type Address = {
  id: string;
  email: string;
  name: string;
  domain: string;
};

export type AuthMe = {
  userId: string;
  username: string;
  isAdmin: boolean;
  activeAddressId: string;
  accessibleAddress: Address[];
};

export type Mailbox = {
  id: string;
  name: string;
  type: string;
  addressId: string;
  uidNext: number;
};

export type MessageSummary = {
  id: string;
  uid: number;
  sender: string;
  recipients: string[];
  subject: string;
  flags: string[];
  createdAt: string;
};

export type MessageDetail = {
  id: string;
  uid: number;
  sender: string;
  recipients: string[];
  flags: string[];
  createdAt: string;
  body: string;
};

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }

  return (await res.json()) as T;
}

export async function login(username: string, password: string): Promise<void> {
  await request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/api/auth/logout", { method: "POST" });
}

export async function authMe(): Promise<AuthMe> {
  return request<AuthMe>("/api/auth/me");
}

export async function setActiveAddress(addressId: string): Promise<void> {
  await request("/api/user/active-address", {
    method: "PUT",
    body: JSON.stringify({ addressId }),
  });
}

export async function listMailboxes(addressId: string): Promise<Mailbox[]> {
  const payload = await request<{ items: Mailbox[] }>(`/api/mailboxes?addressId=${encodeURIComponent(addressId)}`);
  return payload.items;
}

export async function listMessages(addressId: string, mailboxId: string, cursor?: number): Promise<{ items: MessageSummary[]; nextCursor: number; hasMore: boolean; }> {
  const search = new URLSearchParams({ addressId, mailboxId, limit: "50" });
  if (cursor && cursor > 0) {
    search.set("cursor", String(cursor));
  }
  return request(`/api/messages?${search.toString()}`);
}

export async function getMessage(addressId: string, mailboxId: string, messageId: string): Promise<MessageDetail> {
  return request(`/api/messages/${encodeURIComponent(messageId)}?addressId=${encodeURIComponent(addressId)}&mailboxId=${encodeURIComponent(mailboxId)}`);
}

export async function sendMessage(payload: {
  fromAddressId: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  textBody: string;
  htmlBody: string;
}): Promise<void> {
  await request("/api/messages", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateFlags(messageId: string, mailboxId: string, addFlags: string[], removeFlags: string[]): Promise<void> {
  await request(`/api/messages/${encodeURIComponent(messageId)}/flags`, {
    method: "POST",
    body: JSON.stringify({ mailboxId, addFlags, removeFlags }),
  });
}

export async function moveMessage(messageId: string, fromMailboxId: string, toMailboxId: string): Promise<void> {
  await request(`/api/messages/${encodeURIComponent(messageId)}/move`, {
    method: "POST",
    body: JSON.stringify({ fromMailboxId, toMailboxId }),
  });
}

export async function deleteMessage(messageId: string, mailboxId: string): Promise<void> {
  await request(`/api/messages/${encodeURIComponent(messageId)}?mailboxId=${encodeURIComponent(mailboxId)}`, {
    method: "DELETE",
  });
}

export async function listSettings(path: "users" | "domains" | "addresses" | "mailboxes" | "access"): Promise<{ items: unknown[] }> {
  return request(`/api/settings/${path}`);
}
