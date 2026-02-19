import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  authMe,
  deleteMessage,
  getMessage,
  listMailboxes,
  listMessages,
  listSettings,
  login,
  logout,
  moveMessage,
  sendMessage,
  setActiveAddress,
  updateFlags,
  type AuthMe,
  type Mailbox,
  type MessageDetail,
  type MessageSummary,
} from "./lib/api";
import { parseRawMail, type ParsedMail } from "./lib/mail-parser";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  Archive,
  CheckCircle2,
  ChevronRight,
  Clock,
  ExternalLink,
  Inbox,
  LogOut,
  Mail,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  Send,
  Settings,
  Shield,
  Star,
  Trash2,
  User,
  X,
  Menu,
  ChevronDown,
  Circle,
  AlertCircle,
  Eye,
  EyeOff,
  FolderInput
} from "lucide-react";

type Tab = "mail" | "settings";
type SettingsTab = "users" | "domains" | "addresses" | "mailboxes" | "access";
const settingsTabs: SettingsTab[] = ["users", "domains", "addresses", "mailboxes", "access"];

function LoginForm({ onLogin }: { onLogin: () => Promise<void> }): JSX.Element {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      await onLogin();
    } catch {
      setError("Invalid username or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#f8fafc]">
      <div className="absolute inset-0 z-0">
        <div className="absolute top-[-10%] left-[-10%] h-[40%] w-[40%] rounded-full bg-blue-100/50 blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] h-[40%] w-[40%] rounded-full bg-indigo-100/50 blur-[120px]" />
      </div>
      
      <div className="relative z-10 w-full max-w-md px-6">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg shadow-primary/20">
            <Mail className="h-8 w-8" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">Puppy Eyes</h1>
          <p className="mt-2 text-slate-500">Welcome back to your modern inbox</p>
        </div>

        <Card className="border-none shadow-xl ring-1 ring-slate-200">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-xl">Sign in</CardTitle>
            <CardDescription>Enter your credentials to access your account</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <div className="relative">
                  <User className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                  <Input
                    id="username"
                    className="pl-10"
                    placeholder="name@example.com"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password">Password</Label>
                </div>
                <div className="relative">
                  <Shield className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                  <Input
                    id="password"
                    type="password"
                    className="pl-10"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
              </div>
              
              {error && (
                <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm font-medium text-destructive">
                  <AlertCircle className="h-4 w-4" />
                  {error}
                </div>
              )}

              <Button type="submit" className="h-11 w-full text-base" disabled={loading}>
                {loading ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                    Signing in...
                  </>
                ) : "Sign in"}
              </Button>
            </form>
          </CardContent>
        </Card>
        
        <p className="mt-8 text-center text-sm text-slate-500">
          &copy; 2026 Puppy Eyes Mail. All rights reserved.
        </p>
      </div>
    </main>
  );
}

function AppShell({ me, onReloadMe }: { me: AuthMe; onReloadMe: () => Promise<void> }): JSX.Element {
  const [tab, setTab] = useState<Tab>("mail");
  const [activeAddress, setActiveAddressState] = useState(me.activeAddressId);
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [selectedMailbox, setSelectedMailbox] = useState<string>("");
  const [messages, setMessages] = useState<MessageSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<number>(0);
  const [hasMore, setHasMore] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState<MessageDetail | null>(null);
  const [composeOpen, setComposeOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("users");
  const [settingsRows, setSettingsRows] = useState<unknown[]>([]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  const wsRef = useRef<WebSocket | null>(null);

  const activeAddressLabel = useMemo(
    () => me.accessibleAddress.find((address) => address.id === activeAddress)?.email ?? "",
    [activeAddress, me.accessibleAddress],
  );

  const parsedMessage = useMemo(() => {
    if (!selectedMessage) return null;
    return parseRawMail(selectedMessage.body);
  }, [selectedMessage]);

  useEffect(() => {
    void loadMailboxes(activeAddress);
  }, [activeAddress]);

  useEffect(() => {
    if (!selectedMailbox) return;
    void loadMessages(selectedMailbox, true);
    connectMailboxWS(selectedMailbox);
    return () => {
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [selectedMailbox]);

  useEffect(() => {
    if (tab !== "settings") return;
    void loadSettings(settingsTab);
  }, [tab, settingsTab]);

  async function loadMailboxes(addressId: string): Promise<void> {
    const rows = await listMailboxes(addressId);
    setMailboxes(rows);
    if (rows.length > 0) {
      const inbox = rows.find(m => m.name.toUpperCase() === "INBOX") || rows[0];
      setSelectedMailbox(inbox.id);
    } else {
      setSelectedMailbox("");
      setMessages([]);
      setSelectedMessage(null);
    }
  }

  async function loadMessages(mailboxId: string, reset: boolean): Promise<void> {
    const cursor = reset ? undefined : nextCursor;
    const payload = await listMessages(activeAddress, mailboxId, cursor);
    setMessages((prev) => (reset ? payload.items : [...prev, ...payload.items]));
    setNextCursor(payload.nextCursor);
    setHasMore(payload.hasMore);
  }

  async function loadSettings(next: SettingsTab): Promise<void> {
    const payload = await listSettings(next);
    setSettingsRows(payload.items);
  }

  function connectMailboxWS(mailboxId: string): void {
    wsRef.current?.close();
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/mail?mailboxId=${encodeURIComponent(mailboxId)}`);
    ws.onmessage = () => {
      void loadMessages(mailboxId, true);
    };
    wsRef.current = ws;
  }

  async function openMessage(messageId: string): Promise<void> {
    if (!selectedMailbox) return;
    const detail = await getMessage(activeAddress, selectedMailbox, messageId);
    setSelectedMessage(detail);
    if (!detail.flags.includes("\\Seen")) {
      await updateFlags(messageId, selectedMailbox, ["\\Seen"], []);
      // Update local state to avoid full reload
      setMessages(prev => prev.map(m => m.id === messageId ? { ...m, flags: [...m.flags, "\\Seen"] } : m));
    }
  }

  async function onSelectAddress(nextAddressId: string): Promise<void> {
    await setActiveAddress(nextAddressId);
    setActiveAddressState(nextAddressId);
    await onReloadMe();
  }

  async function onDeleteSelected(): Promise<void> {
    if (!selectedMessage || !selectedMailbox) return;
    await onDeleteMessage(selectedMessage.id);
  }

  async function onDeleteMessage(messageId: string): Promise<void> {
    if (!selectedMailbox) return;
    await deleteMessage(messageId, selectedMailbox);
    if (selectedMessage?.id === messageId) setSelectedMessage(null);
    await loadMessages(selectedMailbox, true);
  }

  async function onMoveMessage(messageId: string, toMailboxId: string): Promise<void> {
    if (!selectedMailbox) return;
    await moveMessage(messageId, selectedMailbox, toMailboxId);
    if (selectedMessage?.id === messageId) setSelectedMessage(null);
    await loadMessages(selectedMailbox, true);
  }

  async function onToggleRead(messageId: string, isRead: boolean): Promise<void> {
    if (!selectedMailbox) return;
    const add = isRead ? [] : ["\\Seen"];
    const remove = isRead ? ["\\Seen"] : [];
    await updateFlags(messageId, selectedMailbox, add, remove);
    setMessages(prev => prev.map(m => m.id === messageId ? { ...m, flags: mutateFlagsLocal(m.flags, add, remove) } : m));
    if (selectedMessage?.id === messageId) {
      setSelectedMessage(prev => prev ? { ...prev, flags: mutateFlagsLocal(prev.flags, add, remove) } : null);
    }
  }

  function mutateFlagsLocal(current: string[], add: string[], remove: string[]): string[] {
    const set = new Set(current);
    add.forEach(f => set.add(f));
    remove.forEach(f => set.delete(f));
    return Array.from(set);
  }

  async function onSubmitCompose(form: {
    to: string;
    cc: string;
    bcc: string;
    subject: string;
    textBody: string;
    htmlBody: string;
  }): Promise<void> {
    await sendMessage({
      fromAddressId: activeAddress,
      to: splitEmails(form.to),
      cc: splitEmails(form.cc),
      bcc: splitEmails(form.bcc),
      subject: form.subject,
      textBody: form.textBody,
      htmlBody: form.htmlBody,
    });

    setComposeOpen(false);
    const sent = mailboxes.find((mb) => mb.type === "SENT" || mb.name.toUpperCase() === "SENT");
    if (sent) {
      setSelectedMailbox(sent.id);
      await loadMessages(sent.id, true);
    }
  }

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-background">
      {/* Header */}
      <header className="flex h-14 items-center justify-between border-b px-4 shrink-0">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="lg:hidden">
            <Menu className="h-5 w-5" />
          </Button>
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
              <Mail className="h-5 w-5" />
            </div>
            <span className="text-lg font-bold tracking-tight">Puppy Eyes</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="hidden items-center gap-2 px-3 py-1.5 text-sm font-medium lg:flex">
             <span className="text-muted-foreground">Account:</span>
             <span className="text-foreground">{me.username}</span>
          </div>
          <Separator orientation="vertical" className="mx-2 h-4 hidden lg:block" />
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              void logout().then(() => window.location.reload());
            }}
            className="text-muted-foreground hover:text-foreground"
          >
            <LogOut className="mr-2 h-4 w-4" />
            Sign out
          </Button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside 
          className={cn(
            "fixed inset-y-0 left-0 z-40 w-64 translate-x-[-100%] border-r bg-card transition-transform duration-200 lg:static lg:translate-x-0 shrink-0",
            isSidebarOpen ? "translate-x-0" : ""
          )}
        >
          <div className="flex h-full flex-col">
            <div className="p-4 space-y-4">
              <div className="space-y-2">
                <Label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground px-1">Active Identity</Label>
                <div className="relative">
                  <select
                    className="w-full appearance-none rounded-lg border border-input bg-background px-3 py-2 pr-10 text-sm font-medium outline-none ring-offset-background focus:ring-2 focus:ring-primary/20"
                    value={activeAddress}
                    onChange={(e) => onSelectAddress(e.target.value)}
                  >
                    {me.accessibleAddress.map((address) => (
                      <option key={address.id} value={address.id}>{address.email}</option>
                    ))}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-3 top-2.5 h-4 w-4 text-muted-foreground" />
                </div>
              </div>

              <Button 
                onClick={() => setComposeOpen(true)}
                className="w-full shadow-lg shadow-primary/20 transition-all hover:translate-y-[-1px] active:translate-y-[0px]"
              >
                <Plus className="mr-2 h-4 w-4" />
                Compose
              </Button>
            </div>

            <ScrollArea className="flex-1 px-2">
              <div className="space-y-1 py-2">
                <NavButton 
                  active={tab === "mail"} 
                  onClick={() => setTab("mail")}
                  icon={<Inbox className="h-4 w-4" />}
                  label="Inbox"
                />
                <NavButton 
                  active={tab === "settings"} 
                  onClick={() => setTab("settings")}
                  icon={<Settings className="h-4 w-4" />}
                  label="Settings"
                />
              </div>

              {tab === "mail" && (
                <div className="mt-6 space-y-1">
                  <Label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground px-3 mb-2 block">Mailboxes</Label>
                  {mailboxes.map((mb) => (
                    <button
                      key={mb.id}
                      onClick={() => setSelectedMailbox(mb.id)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                        selectedMailbox === mb.id
                          ? "bg-primary/10 text-primary"
                          : "text-muted-foreground hover:bg-accent hover:text-foreground"
                      )}
                    >
                      <MailboxIcon type={mb.type} className="h-4 w-4" />
                      {mb.name}
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>
          </div>
        </aside>

        {/* Content Area */}
        <main className="flex flex-1 overflow-hidden bg-slate-50/50">
          {tab === "mail" ? (
            <div className="flex flex-1 overflow-hidden">
              {/* Message List Pane */}
              <div className="flex w-full flex-col border-r bg-background lg:w-[380px] shrink-0">
                <div className="flex h-12 items-center justify-between border-b px-4 bg-background shrink-0">
                  <h2 className="font-semibold text-sm">Messages</h2>
                  <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground" onClick={() => loadMessages(selectedMailbox, true)}>
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </div>
                
                <ScrollArea className="flex-1 bg-slate-50/30">
                  <div className="p-2 space-y-1">
                    {messages.length > 0 ? (
                      messages.map((message) => (
                        <MessageListItem
                          key={message.id}
                          message={message}
                          selected={selectedMessage?.id === message.id}
                          onClick={() => openMessage(message.id)}
                          onDelete={onDeleteMessage}
                          onToggleRead={onToggleRead}
                          onMove={onMoveMessage}
                          mailboxes={mailboxes.filter(m => m.id !== selectedMailbox)}
                        />
                      ))
                    ) : (
                      <div className="flex flex-col items-center justify-center p-8 text-center">
                        <Inbox className="h-8 w-8 text-muted-foreground/30 mb-2" />
                        <p className="text-sm font-medium text-muted-foreground">No messages found</p>
                      </div>
                    )}
                    
                    {hasMore && (
                      <div className="p-4">
                        <Button 
                          variant="ghost" 
                          className="w-full text-xs text-muted-foreground" 
                          onClick={() => loadMessages(selectedMailbox, false)}
                        >
                          Load more...
                        </Button>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </div>

              {/* Message View Pane */}
              <div className="hidden flex-1 flex-col overflow-hidden bg-background lg:flex">
                {selectedMessage ? (
                  <div className="flex h-full flex-col overflow-hidden">
                    {/* Message Header Actions */}
                    <div className="flex h-12 items-center justify-between border-b px-4 shrink-0">
                      <div className="flex items-center gap-1">
                        <Button variant="ghost" size="icon" className="h-9 w-9" title="Delete" onClick={onDeleteSelected}>
                          <Trash2 className="h-4 w-4 text-destructive/80" />
                        </Button>
                        <Separator orientation="vertical" className="mx-1 h-4" />
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="h-9 w-9" 
                          title={selectedMessage.flags.includes("\\Seen") ? "Mark as unread" : "Mark as read"} 
                          onClick={() => onToggleRead(selectedMessage.id, selectedMessage.flags.includes("\\Seen"))}
                        >
                          {selectedMessage.flags.includes("\\Seen") ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                      <div className="flex items-center gap-2">
                         <Badge variant={selectedMessage.flags.includes("\\Seen") ? "outline" : "default"}>
                           {selectedMessage.flags.includes("\\Seen") ? "Read" : "Unread"}
                         </Badge>
                      </div>
                    </div>

                    <ScrollArea className="flex-1">
                      <div className="p-8 max-w-4xl mx-auto w-full">
                        <div className="mb-8 space-y-4">
                          <h1 className="text-3xl font-bold tracking-tight text-foreground">
                            {parsedMessage?.headers["subject"] || "(No Subject)"}
                          </h1>
                          
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex items-center gap-3">
                              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-100 text-slate-600 font-semibold uppercase ring-1 ring-slate-200">
                                {selectedMessage.sender.charAt(0) || "?"}
                              </div>
                              <div className="grid gap-0.5">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold">{selectedMessage.sender}</span>
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  To: {selectedMessage.recipients.join(", ")}
                                </div>
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground whitespace-nowrap">
                              {formatDate(selectedMessage.createdAt)}
                            </div>
                          </div>
                        </div>

                        <Separator className="my-8" />

                        <div className="max-w-none">
                          {parsedMessage?.html ? (
                            <div className="rounded-lg border bg-white overflow-hidden h-[600px]">
                              <iframe
                                srcDoc={parsedMessage.html}
                                title="email-content"
                                sandbox="allow-same-origin"
                                className="w-full h-full border-none"
                              />
                            </div>
                          ) : (
                            <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed text-slate-800">
                              {parsedMessage?.text || selectedMessage.body}
                            </pre>
                          )}
                        </div>
                      </div>
                    </ScrollArea>
                  </div>
                ) : (
                  <div className="flex h-full flex-col items-center justify-center text-center p-8">
                    <div className="relative mb-6">
                      <Mail className="h-16 w-16 text-slate-100" />
                      <Circle className="absolute -bottom-1 -right-1 h-6 w-6 text-slate-50 fill-slate-50" />
                      <Search className="absolute -bottom-1 -right-1 h-6 w-6 text-slate-300" />
                    </div>
                    <h3 className="text-lg font-semibold text-slate-900">No message selected</h3>
                    <p className="mt-2 text-sm text-slate-500 max-w-xs">
                      Select a message from the list on the left to read its contents and take action.
                    </p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 overflow-hidden flex flex-col">
              <div className="flex h-12 items-center justify-between border-b px-6 bg-background shrink-0">
                <h2 className="font-semibold text-sm">System Settings</h2>
                <Badge variant="secondary" className="font-normal text-[10px]">
                  {me.isAdmin ? "Administrator" : "User Access"}
                </Badge>
              </div>
              
              <ScrollArea className="flex-1 p-6">
                <div className="max-w-5xl mx-auto">
                  <Tabs value={settingsTab} onValueChange={(value) => setSettingsTab(value as SettingsTab)}>
                    <TabsList className="grid w-full grid-cols-5 mb-8 bg-muted/50 p-1">
                      <TabsTrigger value="users" className="data-[state=active]:shadow-sm">Users</TabsTrigger>
                      <TabsTrigger value="domains" className="data-[state=active]:shadow-sm">Domains</TabsTrigger>
                      <TabsTrigger value="addresses" className="data-[state=active]:shadow-sm">Addresses</TabsTrigger>
                      <TabsTrigger value="mailboxes" className="data-[state=active]:shadow-sm">Mailboxes</TabsTrigger>
                      <TabsTrigger value="access" className="data-[state=active]:shadow-sm">Access</TabsTrigger>
                    </TabsList>

                    {settingsTabs.map((name) => (
                      <TabsContent key={name} value={name} className="mt-0">
                        <div className="grid gap-6">
                          {settingsRows.length > 0 ? (
                            settingsRows.map((row, idx) => (
                              <SettingsCard key={`${name}-${idx}`} row={row} type={name} />
                            ))
                          ) : (
                            <div className="flex flex-col items-center justify-center p-12 border-2 border-dashed rounded-xl bg-slate-50/50">
                              <Settings className="h-10 w-10 text-slate-200 mb-3" />
                              <p className="text-sm font-medium text-slate-500">No {name} found</p>
                            </div>
                          )}
                        </div>
                      </TabsContent>
                    ))}
                  </Tabs>
                </div>
              </ScrollArea>
            </div>
          )}
        </main>
      </div>

      <ComposeDialog open={composeOpen} onOpenChange={setComposeOpen} onSubmit={onSubmitCompose} />
    </div>
  );
}

function NavButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all",
        active
          ? "bg-primary text-primary-foreground shadow-sm shadow-primary/20"
          : "text-muted-foreground hover:bg-accent hover:text-foreground"
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function MailboxIcon({ type, ...props }: { type: string } & React.SVGAttributes<SVGElement>) {
  switch (type.toUpperCase()) {
    case "INBOX": return <Inbox {...props} />;
    case "SENT": return <Send {...props} />;
    case "TRASH": return <Trash2 {...props} />;
    case "ARCHIVE": return <Archive {...props} />;
    case "JUNK": return <Shield {...props} />;
    case "DRAFTS": return <Clock {...props} />;
    default: return <Mail {...props} />;
  }
}

function MessageListItem({ 
  message, 
  selected, 
  onClick,
  onDelete,
  onToggleRead,
  onMove,
  mailboxes
}: { 
  message: MessageSummary; 
  selected: boolean; 
  onClick: () => void;
  onDelete: (id: string) => void;
  onToggleRead: (id: string, isRead: boolean) => void;
  onMove: (id: string, toMailboxId: string) => void;
  mailboxes: Mailbox[];
}) {
  const isUnread = !message.flags.includes("\\Seen");
  
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <button
          onClick={onClick}
          className={cn(
            "group relative flex w-full flex-col items-start gap-1 rounded-lg p-3 text-left transition-all outline-none",
            selected 
              ? "bg-primary/5 ring-1 ring-inset ring-primary/20" 
              : "hover:bg-slate-100/80"
          )}
        >
          <div className="flex w-full items-center justify-between gap-2">
            <div className="flex items-center gap-2 overflow-hidden">
              {isUnread && <div className="h-2 w-2 rounded-full bg-primary shrink-0" />}
              <span className={cn("truncate text-sm", isUnread ? "font-bold text-foreground" : "font-medium text-muted-foreground")}>
                {message.sender}
              </span>
            </div>
            <span className="text-[10px] text-muted-foreground whitespace-nowrap">
              {new Date(message.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric' })}
            </span>
          </div>
          
          <span className={cn("w-full truncate text-sm", isUnread ? "font-semibold text-foreground" : "text-muted-foreground")}>
            {message.subject || "(No Subject)"}
          </span>
          
          <div className="flex items-center gap-2 mt-0.5">
            {message.flags.includes("\\Starred") && <Star className="h-3 w-3 text-amber-400 fill-amber-400" />}
            {message.flags.includes("\\Draft") && <Badge variant="outline" className="h-4 px-1 text-[8px] uppercase">Draft</Badge>}
          </div>
        </button>
      </ContextMenuTrigger>
      <ContextMenuContent className="w-48">
        <ContextMenuItem onClick={() => onToggleRead(message.id, !isUnread)}>
          {!isUnread ? <EyeOff className="mr-2 h-4 w-4" /> : <Eye className="mr-2 h-4 w-4" />}
          <span>Mark as {!isUnread ? "unread" : "read"}</span>
        </ContextMenuItem>
        
        <ContextMenuSub>
          <ContextMenuSubTrigger>
            <FolderInput className="mr-2 h-4 w-4" />
            <span>Move to</span>
          </ContextMenuSubTrigger>
          <ContextMenuSubContent className="w-48">
            {mailboxes.length > 0 ? (
              mailboxes.map(mb => (
                <ContextMenuItem key={mb.id} onClick={() => onMove(message.id, mb.id)}>
                   <MailboxIcon type={mb.type} className="mr-2 h-4 w-4" />
                   <span>{mb.name}</span>
                </ContextMenuItem>
              ))
            ) : (
              <ContextMenuItem disabled>No other mailboxes</ContextMenuItem>
            )}
          </ContextMenuSubContent>
        </ContextMenuSub>

        <ContextMenuSeparator />
        
        <ContextMenuItem onClick={() => onDelete(message.id)} className="text-destructive focus:text-destructive">
          <Trash2 className="mr-2 h-4 w-4" />
          <span>Delete</span>
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

function SettingsCard({ row, type }: { row: any, type: string }) {
  const entries = Object.entries(row);
  return (
    <Card className="border-none shadow-sm ring-1 ring-slate-200 overflow-hidden">
      <div className="bg-slate-50/50 border-b px-4 py-2 flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">{type} Details</span>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-6 w-6"><ExternalLink className="h-3 w-3" /></Button>
          <Button variant="ghost" size="icon" className="h-6 w-6"><MoreVertical className="h-3 w-3" /></Button>
        </div>
      </div>
      <CardContent className="p-4 grid gap-4 sm:grid-cols-2 md:grid-cols-3">
        {entries.map(([key, value]) => (
          <div key={key} className="space-y-1">
            <Label className="text-[10px] font-bold uppercase text-slate-400 tracking-tight">{prettyLabel(key)}</Label>
            <div className="text-sm font-medium text-slate-700 truncate bg-slate-100/50 px-2 py-1 rounded">
              {toDisplayValue(value)}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function ComposeDialog({
  open,
  onOpenChange,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (payload: {
    to: string;
    cc: string;
    bcc: string;
    subject: string;
    textBody: string;
    htmlBody: string;
  }) => Promise<void>;
}): JSX.Element {
  const [to, setTo] = useState("");
  const [cc, setCc] = useState("");
  const [bcc, setBcc] = useState("");
  const [subject, setSubject] = useState("");
  const [textBody, setTextBody] = useState("");
  const [htmlBody, setHTMLBody] = useState("");
  const [loading, setLoading] = useState(false);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl p-0 gap-0 border-none shadow-2xl overflow-hidden ring-1 ring-slate-200">
        <DialogHeader className="px-6 py-4 bg-slate-50 border-b">
          <div className="flex items-center justify-between">
            <div>
              <DialogTitle className="text-lg">New Message</DialogTitle>
              <DialogDescription className="text-xs">Create and send a rich multipart email</DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="flex flex-col max-h-[80vh]">
          <div className="p-6 space-y-4 overflow-y-auto">
            <div className="grid gap-3">
              <div className="flex items-center gap-4">
                <Label htmlFor="compose-to" className="w-16 text-right text-muted-foreground">To</Label>
                <Input
                  id="compose-to"
                  className="flex-1 border-none shadow-none focus-visible:ring-0 bg-slate-50"
                  placeholder="recipients@example.com"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                />
              </div>
              <Separator />
              <div className="flex items-center gap-4">
                <Label htmlFor="compose-cc" className="w-16 text-right text-muted-foreground">Cc</Label>
                <Input id="compose-cc" className="flex-1 border-none shadow-none focus-visible:ring-0" value={cc} onChange={(e) => setCc(e.target.value)} />
              </div>
              <Separator />
              <div className="flex items-center gap-4">
                <Label htmlFor="compose-bcc" className="w-16 text-right text-muted-foreground">Bcc</Label>
                <Input id="compose-bcc" className="flex-1 border-none shadow-none focus-visible:ring-0" value={bcc} onChange={(e) => setBcc(e.target.value)} />
              </div>
              <Separator />
              <div className="flex items-center gap-4">
                <Label htmlFor="compose-subject" className="w-16 text-right text-muted-foreground">Subject</Label>
                <Input
                  id="compose-subject"
                  className="flex-1 border-none shadow-none font-semibold focus-visible:ring-0"
                  placeholder="Subject"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>
              <Separator />
            </div>

            <Tabs defaultValue="text" className="w-full">
              <TabsList className="grid w-full grid-cols-2 mb-4 bg-muted/30">
                <TabsTrigger value="text">Plain Text</TabsTrigger>
                <TabsTrigger value="html">HTML Version</TabsTrigger>
              </TabsList>
              <TabsContent value="text" className="mt-0">
                <Textarea 
                  id="compose-text" 
                  value={textBody} 
                  onChange={(e) => setTextBody(e.target.value)} 
                  placeholder="Write your plain text message here..."
                  className="min-h-[200px] border-none shadow-none focus-visible:ring-0 bg-slate-50/50" 
                />
              </TabsContent>
              <TabsContent value="html" className="mt-0">
                <Textarea 
                  id="compose-html" 
                  value={htmlBody} 
                  onChange={(e) => setHTMLBody(e.target.value)} 
                  placeholder="<html><body><h1>Hello!</h1></body></html>"
                  className="min-h-[200px] font-mono text-xs border-none shadow-none focus-visible:ring-0 bg-slate-50/50" 
                />
              </TabsContent>
            </Tabs>
          </div>

          <DialogFooter className="p-4 bg-slate-50 border-t flex items-center justify-between">
            <div className="flex items-center gap-2">
               <Button variant="ghost" size="icon" className="h-9 w-9 text-muted-foreground"><Trash2 className="h-4 w-4" /></Button>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="ghost" onClick={() => onOpenChange(false)}>Discard</Button>
              <Button
                disabled={loading}
                className="px-8 shadow-lg shadow-primary/20"
                onClick={async () => {
                  setLoading(true);
                  try {
                    await onSubmit({ to, cc, bcc, subject, textBody, htmlBody });
                  } finally {
                    setLoading(false);
                  }
                }}
              >
                {loading ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                Send Message
              </Button>
            </div>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Helper functions (preserved from original)
function splitEmails(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function extractHeader(raw: string, header: string): string {
  const lines = raw.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "") break;
    if (trimmed.toLowerCase().startsWith(`${header.toLowerCase()}:`)) {
      return trimmed.slice(header.length + 1).trim();
    }
  }
  return "";
}

function formatDate(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString([], { dateStyle: 'long', timeStyle: 'short' });
}

function toDisplayValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function prettyLabel(key: string): string {
  return key.replace(/([A-Z])/g, " $1").replace(/[_-]/g, " ").trim();
}

export default function App(): JSX.Element {
  const [me, setMe] = useState<AuthMe | null>(null);
  const [ready, setReady] = useState(false);

  const load = async (): Promise<void> => {
    try {
      const payload = await authMe();
      setMe(payload);
    } catch {
      setMe(null);
    } finally {
      setReady(true);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  if (!ready) {
    return (
      <main className="grid min-h-screen place-items-center bg-slate-50">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 rounded-2xl bg-primary flex items-center justify-center animate-pulse shadow-lg shadow-primary/20">
            <Mail className="h-6 w-6 text-primary-foreground" />
          </div>
          <p className="text-sm font-medium text-slate-500">Preparing your inbox...</p>
        </div>
      </main>
    );
  }

  if (!me) {
    return <LoginForm onLogin={load} />;
  }

  return <AppShell me={me} onReloadMe={load} />;
}

