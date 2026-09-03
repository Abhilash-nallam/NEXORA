import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActivityIndicator, Alert, FlatList, KeyboardAvoidingView, Modal, Platform,
  Pressable, SafeAreaView, ScrollView, Share, StyleSheet, Switch, Text, TextInput,
  TouchableOpacity, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as OTPAuth from 'otpauth';
import { createBackup, restoreBackup } from './src/backup';

export type Account = {
  id: string; issuer: string; account: string; algorithm: string; digits: number;
  period: number; createdAt: number;
};

const META_KEY = 'nexora.accounts.v1';
const SETTINGS_KEY = 'nexora.settings.v1';
const ONBOARDED_KEY = 'nexora.onboarded.v1';
const SECRET_PREFIX = 'nexora.secret.v1.';

type Settings = { biometric: boolean; autoLock: boolean; hideCodes: boolean };
const defaultSettings: Settings = { biometric: true, autoLock: true, hideCodes: false };

const uid = () => Crypto.randomUUID();
const secretKey = (id: string) => `${SECRET_PREFIX}${id}`;

async function readAccounts(): Promise<Account[]> {
  const raw = await AsyncStorage.getItem(META_KEY);
  return raw ? JSON.parse(raw) : [];
}
async function saveAccounts(accounts: Account[]) { await AsyncStorage.setItem(META_KEY, JSON.stringify(accounts)); }
async function getSecret(id: string) { return SecureStore.getItemAsync(secretKey(id)); }
async function saveSecret(id: string, secret: string) {
  await SecureStore.setItemAsync(secretKey(id), secret, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
}
async function deleteSecret(id: string) { await SecureStore.deleteItemAsync(secretKey(id)); }

function normalizeSecret(input: string) {
  return input.replace(/[\s-]/g, '').toUpperCase();
}

function parseOtpUri(uri: string) {
  if (!uri.toLowerCase().startsWith('otpauth://totp/')) throw new Error('Only TOTP QR codes are supported.');
  const parsed = OTPAuth.URI.parse(uri);
  if (!(parsed instanceof OTPAuth.TOTP)) throw new Error('Unsupported OTP type.');
  if (!parsed.secret?.base32) throw new Error('QR code does not contain a secret.');
  const issuer = (parsed.issuer || '').trim();
  const account = (parsed.label || '').trim();
  if (!account) throw new Error('QR code has no account label.');
  return {
    issuer: issuer || 'Unknown', account, secret: normalizeSecret(parsed.secret.base32),
    algorithm: parsed.algorithm || 'SHA1', digits: parsed.digits || 6, period: parsed.period || 30,
  };
}

function makeTotp(account: Account, secret: string) {
  return new OTPAuth.TOTP({ issuer: account.issuer, label: account.account, secret, algorithm: account.algorithm, digits: account.digits, period: account.period });
}

function getCode(account: Account, secret: string, now: number) {
  try { return makeTotp(account, secret).generate({ timestamp: now }); } catch { return '------'; }
}

function remaining(account: Account, now: number) {
  const elapsed = Math.floor(now / 1000) % account.period;
  return account.period - elapsed;
}

function initials(name: string) {
  const words = name.trim().split(/\s+/).filter(Boolean);
  return (words.length > 1 ? words[0][0] + words[1][0] : words[0]?.slice(0, 2) || 'NX').toUpperCase();
}

export default function App() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [onboarded, setOnboarded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [screen, setScreen] = useState<'home' | 'add' | 'settings' | 'edit' | 'backup'>('home');
  const [editing, setEditing] = useState<Account | null>(null);
  const [toast, setToast] = useState('');
  const backgroundRef = useRef(false);

  const showToast = useCallback((msg: string) => { setToast(msg); setTimeout(() => setToast(''), 1800); }, []);

  const loadSecrets = useCallback(async (list: Account[]) => {
    const entries = await Promise.all(list.map(async a => [a.id, await getSecret(a.id)] as const));
    const next: Record<string, string> = {};
    for (const [id, value] of entries) if (value) next[id] = value;
    setSecrets(next);
  }, []);

  const authenticate = useCallback(async () => {
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    const enrolled = await LocalAuthentication.isEnrolledAsync();
    if (!hasHardware || !enrolled) return false;
    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: 'Unlock NEXORA',
      cancelLabel: 'Cancel', fallbackLabel: 'Use device passcode', disableDeviceFallback: false,
      biometricsSecurityLevel: 'strong',
    });
    return result.success;
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [a, sRaw, ob] = await Promise.all([readAccounts(), AsyncStorage.getItem(SETTINGS_KEY), AsyncStorage.getItem(ONBOARDED_KEY)]);
        const s = sRaw ? { ...defaultSettings, ...JSON.parse(sRaw) } : defaultSettings;
        setAccounts(a); setSettings(s); setOnboarded(ob === '1');
        if (ob === '1' && s.biometric && a.length) setLocked(true);
        else await loadSecrets(a);
      } catch (e) { Alert.alert('NEXORA', 'Could not load the secure vault.'); }
      finally { setLoading(false); }
    })();
  }, [loadSecrets]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const sub = require('react-native').AppState.addEventListener('change', async (state: string) => {
      if (state !== 'active') backgroundRef.current = true;
      if (state === 'active' && backgroundRef.current && settings.autoLock && settings.biometric && accounts.length) {
        backgroundRef.current = false; setLocked(true); setSecrets({});
      }
    });
    return () => sub.remove();
  }, [accounts.length, settings.autoLock, settings.biometric]);

  const unlock = async () => {
    const ok = await authenticate();
    if (ok) { await loadSecrets(accounts); setLocked(false); }
    else showToast('Authentication cancelled');
  };

  const updateSettings = async (next: Settings) => {
    setSettings(next); await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
    if (next.biometric && accounts.length) { const ok = await authenticate(); if (!ok) { const rollback = { ...next, biometric: false }; setSettings(rollback); await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(rollback)); showToast('Biometric protection not enabled'); } }
  };

  const addAccount = async (data: { issuer: string; account: string; secret: string; algorithm: string; digits: number; period: number }) => {
    const secret = normalizeSecret(data.secret);
    if (!/^[A-Z2-7]+=*$/.test(secret) || secret.length < 8) throw new Error('Enter a valid Base32 secret.');
    const id = uid();
    const account: Account = { id, issuer: data.issuer.trim() || 'Unknown', account: data.account.trim(), algorithm: data.algorithm, digits: data.digits, period: data.period, createdAt: Date.now() };
    if (!account.account) throw new Error('Account name is required.');
    const code = getCode(account, secret, Date.now()); if (!/^\d+$/.test(code)) throw new Error('The secret could not generate a TOTP code.');
    await saveSecret(id, secret); const next = [...accounts, account]; await saveAccounts(next); setAccounts(next); setSecrets(v => ({ ...v, [id]: secret })); setScreen('home'); showToast('Account added');
  };

  const editAccount = async (data: Partial<Account> & { secret?: string }) => {
    if (!editing) return;
    const nextAccount = { ...editing, ...data } as Account;
    if (!nextAccount.account.trim()) throw new Error('Account name is required.');
    if (data.secret) await saveSecret(editing.id, normalizeSecret(data.secret));
    const next = accounts.map(a => a.id === editing.id ? nextAccount : a); await saveAccounts(next); setAccounts(next);
    if (data.secret) setSecrets(v => ({ ...v, [editing.id]: normalizeSecret(data.secret!) }));
    setEditing(null); setScreen('home'); showToast('Account updated');
  };

  const removeAccount = (account: Account) => {
    Alert.alert('Delete account?', `${account.issuer} • ${account.account}`, [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Delete', style: 'destructive', onPress: async () => { await deleteSecret(account.id); const next = accounts.filter(a => a.id !== account.id); await saveAccounts(next); setAccounts(next); setSecrets(v => { const n = { ...v }; delete n[account.id]; return n; }); showToast('Account deleted'); } },
    ]);
  };

  const copyCode = async (account: Account) => { const code = getCode(account, secrets[account.id] || '', now); await Clipboard.setStringAsync(code); showToast('Code copied'); };

  const backupExport = async (password: string) => {
    if (password.length < 10) throw new Error('Use at least 10 characters for the backup password.');
    const payload = await Promise.all(accounts.map(async a => {
      const secret = await getSecret(a.id);
      if (!secret) throw new Error(`Could not read the secret for ${a.issuer}.`);
      return { ...a, secret };
    }));
    const backup = await createBackup(payload, password); await Share.share({ message: backup, title: 'NEXORA encrypted backup' }); showToast('Encrypted backup created');
  };
  const backupImport = async (backup: string, password: string) => {
    const imported = await restoreBackup(backup.trim(), password);
    let added = 0;
    const currentKeys = new Set(accounts.map(a => `${a.issuer}\u0000${a.account}`.toLowerCase()));
    const next = [...accounts]; const nextSecrets = { ...secrets };
    for (const item of imported) {
      if (!item.secret) throw new Error(`Backup account "${item.account}" is missing its secret.`);
      const key = `${item.issuer}\u0000${item.account}`.toLowerCase();
      if (currentKeys.has(key)) continue;
      const a: Account = { id: uid(), issuer: item.issuer, account: item.account, algorithm: item.algorithm, digits: item.digits, period: item.period, createdAt: item.createdAt || Date.now() };
      await saveSecret(a.id, item.secret); next.push(a); nextSecrets[a.id] = item.secret; currentKeys.add(key); added++;
    }
    await saveAccounts(next); setAccounts(next); setSecrets(nextSecrets); setScreen('home'); showToast(`${added} account${added === 1 ? '' : 's'} restored`);
  };

  if (loading) return <Splash />;
  if (!onboarded) return <Onboarding onDone={async (useBiometric) => { const next = { ...settings, biometric: useBiometric }; await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); await AsyncStorage.setItem(ONBOARDED_KEY, '1'); setSettings(next); setOnboarded(true); }} />;
  if (locked) return <LockScreen onUnlock={unlock} />;

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      <View style={styles.header}><View><Text style={styles.brand}>NEXORA</Text><Text style={styles.subtitle}>Secure authenticator</Text></View><Pressable style={styles.headerButton} onPress={() => setScreen('settings')}><Text style={styles.headerIcon}>⚙</Text></Pressable></View>
      {screen === 'home' && <Home accounts={accounts} secrets={secrets} now={now} hideCodes={settings.hideCodes} onAdd={() => setScreen('add')} onCopy={copyCode} onEdit={(a: Account) => { setEditing(a); setScreen('edit'); }} onDelete={removeAccount} />}
      {screen === 'add' && <AddAccount onBack={() => setScreen('home')} onSave={addAccount} />}
      {screen === 'settings' && <SettingsView settings={settings} accounts={accounts.length} onBack={() => setScreen('home')} onChange={updateSettings} onBackup={() => setScreen('backup')} onLock={() => { setLocked(true); setSecrets({}); }} />}
      {screen === 'edit' && editing && <EditAccount account={editing} secret={secrets[editing.id] || ''} onBack={() => { setEditing(null); setScreen('home'); }} onSave={editAccount} />}
      {screen === 'backup' && <BackupView onBack={() => setScreen('settings')} onExport={backupExport} onImport={backupImport} />}
      {toast ? <View style={styles.toast}><Text style={styles.toastText}>{toast}</Text></View> : null}
    </SafeAreaView>
  );
}

function Splash() { return <View style={styles.splash}><Text style={styles.splashLogo}>N</Text><Text style={styles.splashTitle}>NEXORA</Text><Text style={styles.splashSub}>Secure authentication, offline.</Text><ActivityIndicator style={{ marginTop: 28 }} /></View>; }

function Onboarding({ onDone }: { onDone: (biometric: boolean) => void }) {
  const [biometric, setBiometric] = useState(true); const [available, setAvailable] = useState(false);
  useEffect(() => { (async () => setAvailable((await LocalAuthentication.hasHardwareAsync()) && (await LocalAuthentication.isEnrolledAsync())))(); }, []);
  return <SafeAreaView style={styles.root}><StatusBar style="light" /><View style={styles.onboard}><View style={styles.logoCircle}><Text style={styles.logoText}>N</Text></View><Text style={styles.hero}>Your codes.<Text style={styles.heroAccent}> Your device.</Text></Text><Text style={styles.onboardText}>NEXORA generates one-time passwords locally. Your authenticator secrets stay on this device and never need an internet connection.</Text><View style={styles.securityCard}><Text style={styles.cardTitle}>🔐 Private by design</Text><Text style={styles.cardText}>SecureStore-backed secrets, optional biometric app lock, encrypted backups and no account required.</Text></View>{available && <View style={styles.row}><View><Text style={styles.rowTitle}>Protect with biometrics</Text><Text style={styles.rowSub}>Fingerprint, face or device passcode</Text></View><Switch value={biometric} onValueChange={setBiometric} /></View>}<Pressable style={styles.primary} onPress={() => onDone(available && biometric)}><Text style={styles.primaryText}>Get started</Text></Pressable></View></SafeAreaView>;
}

function LockScreen({ onUnlock }: { onUnlock: () => void }) { return <SafeAreaView style={styles.root}><StatusBar style="light" /><View style={styles.lock}><View style={styles.logoCircle}><Text style={styles.logoText}>N</Text></View><Text style={styles.lockTitle}>NEXORA is locked</Text><Text style={styles.lockText}>Authenticate to access your authenticator codes.</Text><Pressable style={styles.primary} onPress={onUnlock}><Text style={styles.primaryText}>Unlock</Text></Pressable></View></SafeAreaView>; }

function Home({ accounts, secrets, now, hideCodes, onAdd, onCopy, onEdit, onDelete }: any) {
  return <View style={styles.flex}><View style={styles.homeIntro}><View><Text style={styles.sectionTitle}>Your accounts</Text><Text style={styles.sectionSub}>{accounts.length} protected {accounts.length === 1 ? 'account' : 'accounts'}</Text></View><Pressable style={styles.addButton} onPress={onAdd}><Text style={styles.addText}>＋ Add</Text></Pressable></View>{accounts.length === 0 ? <View style={styles.empty}><Text style={styles.emptyIcon}>＋</Text><Text style={styles.emptyTitle}>No accounts yet</Text><Text style={styles.emptyText}>Scan a QR code or enter a secret to create your first authenticator account.</Text><Pressable style={styles.primarySmall} onPress={onAdd}><Text style={styles.primaryText}>Add account</Text></Pressable></View> : <FlatList data={accounts} keyExtractor={(a: Account) => a.id} contentContainerStyle={styles.list} renderItem={({ item }: any) => <AccountCard account={item} secret={secrets[item.id]} now={now} hideCodes={hideCodes} onCopy={() => onCopy(item)} onEdit={() => onEdit(item)} onDelete={() => onDelete(item)} />} />}</View>;
}

function AccountCard({ account, secret, now, hideCodes, onCopy, onEdit, onDelete }: any) {
  const code = secret ? getCode(account, secret, now) : '------'; const left = remaining(account, now); const progress = Math.max(0, Math.min(1, left / account.period));
  return <View style={styles.accountCard}><View style={styles.accountTop}><View style={styles.avatar}><Text style={styles.avatarText}>{initials(account.issuer)}</Text></View><View style={styles.accountInfo}><Text style={styles.issuer}>{account.issuer}</Text><Text style={styles.accountName} numberOfLines={1}>{account.account}</Text></View><Pressable onPress={onEdit} style={styles.more}><Text style={styles.moreText}>•••</Text></Pressable></View><Pressable onPress={onCopy} style={styles.codeArea}><Text style={styles.code}>{hideCodes ? '••••••' : `${code.slice(0, 3)} ${code.slice(3)}`}</Text><Text style={styles.copyHint}>Tap to copy</Text></Pressable><View style={styles.timerRow}><View style={styles.track}><View style={[styles.progress, { width: `${progress * 100}%` }]} /></View><Text style={styles.timer}>{left}s</Text></View><View style={styles.cardActions}><Pressable onPress={onEdit}><Text style={styles.actionText}>Edit</Text></Pressable><Pressable onPress={onDelete}><Text style={styles.deleteText}>Delete</Text></Pressable></View></View>;
}

function AddAccount({ onBack, onSave }: any) {
  const [mode, setMode] = useState<'scan' | 'manual'>('scan'); const [permission, requestPermission] = useCameraPermissions(); const [scanned, setScanned] = useState(false); const [issuer, setIssuer] = useState(''); const [account, setAccount] = useState(''); const [secret, setSecret] = useState(''); const [algorithm, setAlgorithm] = useState('SHA1'); const [digits, setDigits] = useState('6'); const [period, setPeriod] = useState('30'); const [saving, setSaving] = useState(false);
  const save = async () => { try { setSaving(true); await onSave({ issuer, account, secret, algorithm, digits: Number(digits), period: Number(period) }); } catch (e: any) { Alert.alert('Could not add account', e.message || 'Invalid account.'); } finally { setSaving(false); } };
  const scan = ({ data }: any) => { if (scanned) return; setScanned(true); try { const p = parseOtpUri(data); setIssuer(p.issuer); setAccount(p.account); setSecret(p.secret); setAlgorithm(p.algorithm); setDigits(String(p.digits)); setPeriod(String(p.period)); setMode('manual'); } catch (e: any) { Alert.alert('Unsupported QR code', e.message); setScanned(false); } };
  return <View style={styles.flex}><View style={styles.subHeader}><Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable><Text style={styles.subHeaderTitle}>Add account</Text><View style={{ width: 50 }} /></View><View style={styles.tabs}><Pressable style={[styles.tab, mode === 'scan' && styles.tabActive]} onPress={() => setMode('scan')}><Text style={[styles.tabText, mode === 'scan' && styles.tabTextActive]}>Scan QR</Text></Pressable><Pressable style={[styles.tab, mode === 'manual' && styles.tabActive]} onPress={() => setMode('manual')}><Text style={[styles.tabText, mode === 'manual' && styles.tabTextActive]}>Enter manually</Text></Pressable></View>{mode === 'scan' ? <View style={styles.scannerWrap}>{!permission?.granted ? <View style={styles.permission}><Text style={styles.emptyIcon}>▣</Text><Text style={styles.emptyTitle}>Camera access</Text><Text style={styles.emptyText}>NEXORA uses the camera only to read an authenticator QR code.</Text><Pressable style={styles.primarySmall} onPress={requestPermission}><Text style={styles.primaryText}>Allow camera</Text></Pressable></View> : <CameraView style={styles.camera} facing="back" barcodeScannerSettings={{ barcodeTypes: ['qr'] }} onBarcodeScanned={scan}><View style={styles.scanFrame} /></CameraView>}</View> : <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}><ScrollView contentContainerStyle={styles.form}><Field label="Issuer / service" value={issuer} onChangeText={setIssuer} placeholder="e.g. GitHub" /><Field label="Account" value={account} onChangeText={setAccount} placeholder="e.g. you@example.com" autoCapitalize="none" /><Field label="Secret key (Base32)" value={secret} onChangeText={setSecret} placeholder="JBSWY3DPEHPK3PXP" autoCapitalize="characters" secureTextEntry /><Text style={styles.fieldLabel}>Algorithm</Text><View style={styles.choiceRow}>{['SHA1', 'SHA256', 'SHA512'].map(v => <Pressable key={v} style={[styles.choice, algorithm === v && styles.choiceActive]} onPress={() => setAlgorithm(v)}><Text style={styles.choiceText}>{v}</Text></Pressable>)}</View><Text style={styles.fieldLabel}>Digits</Text><View style={styles.choiceRow}>{['6', '8'].map(v => <Pressable key={v} style={[styles.choice, digits === v && styles.choiceActive]} onPress={() => setDigits(v)}><Text style={styles.choiceText}>{v}</Text></Pressable>)}</View><Field label="Period (seconds)" value={period} onChangeText={setPeriod} keyboardType="number-pad" /><Pressable style={styles.primary} onPress={save} disabled={saving}>{saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>Add account</Text>}</Pressable></ScrollView></KeyboardAvoidingView>}</View>;
}

function EditAccount({ account, secret, onBack, onSave }: any) { const [issuer, setIssuer] = useState(account.issuer); const [name, setName] = useState(account.account); const [newSecret, setNewSecret] = useState(''); return <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}><View style={styles.subHeader}><Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable><Text style={styles.subHeaderTitle}>Edit account</Text><View style={{ width: 50 }} /></View><ScrollView contentContainerStyle={styles.form}><Field label="Issuer / service" value={issuer} onChangeText={setIssuer} /><Field label="Account" value={name} onChangeText={setName} autoCapitalize="none" /><Field label="Replace secret (optional)" value={newSecret} onChangeText={setNewSecret} placeholder="Leave blank to keep current" autoCapitalize="characters" secureTextEntry /><View style={styles.infoBox}><Text style={styles.infoTitle}>Secret protection</Text><Text style={styles.infoText}>The current secret is stored in the device secure store. It is never shown in full here.</Text></View><Pressable style={styles.primary} onPress={() => onSave({ issuer, account: name, secret: newSecret || undefined })}><Text style={styles.primaryText}>Save changes</Text></Pressable></ScrollView></KeyboardAvoidingView>; }

function SettingsView({ settings, accounts, onBack, onChange, onBackup, onLock }: any) { return <View style={styles.flex}><View style={styles.subHeader}><Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable><Text style={styles.subHeaderTitle}>Settings</Text><View style={{ width: 50 }} /></View><ScrollView contentContainerStyle={styles.settings}><Text style={styles.settingsSection}>Security</Text><SettingRow title="Biometric lock" subtitle="Require authentication when opening NEXORA" value={settings.biometric} onValueChange={(v: boolean) => onChange({ ...settings, biometric: v })} /><SettingRow title="Auto-lock" subtitle="Lock when NEXORA leaves the foreground" value={settings.autoLock} onValueChange={(v: boolean) => onChange({ ...settings, autoLock: v })} /><SettingRow title="Hide codes" subtitle="Mask one-time passwords on the home screen" value={settings.hideCodes} onValueChange={(v: boolean) => onChange({ ...settings, hideCodes: v })} /><Text style={styles.settingsSection}>Vault</Text><Pressable style={styles.settingButton} onPress={onBackup}><Text style={styles.settingButtonTitle}>Encrypted backup & restore</Text><Text style={styles.settingButtonSub}>Export or import your accounts using a password-protected backup</Text></Pressable><Pressable style={styles.settingButton} onPress={onLock}><Text style={styles.settingButtonTitle}>Lock now</Text><Text style={styles.settingButtonSub}>{accounts} accounts protected on this device</Text></Pressable><Text style={styles.footer}>NEXORA stores authenticator secrets locally. Normal code generation is offline and does not require an account or server.</Text></ScrollView></View>; }
function SettingRow({ title, subtitle, value, onValueChange }: any) { return <View style={styles.settingRow}><View style={{ flex: 1 }}><Text style={styles.rowTitle}>{title}</Text><Text style={styles.rowSub}>{subtitle}</Text></View><Switch value={value} onValueChange={onValueChange} /> </View>; }

function BackupView({ onBack, onExport, onImport }: any) { const [password, setPassword] = useState(''); const [backup, setBackup] = useState(''); const [busy, setBusy] = useState(false); const run = async (fn: any) => { try { setBusy(true); await fn(password, backup); setPassword(''); setBackup(''); } catch (e: any) { Alert.alert('Backup error', e.message || 'Could not complete backup operation.'); } finally { setBusy(false); } }; return <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}><View style={styles.subHeader}><Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable><Text style={styles.subHeaderTitle}>Backup & restore</Text><View style={{ width: 50 }} /></View><ScrollView contentContainerStyle={styles.form}><View style={styles.infoBox}><Text style={styles.infoTitle}>Encrypted backup</Text><Text style={styles.infoText}>Backups contain your authenticator secrets. NEXORA encrypts them with your password before sharing. Never share the password with anyone.</Text></View><Field label="Backup password" value={password} onChangeText={setPassword} secureTextEntry placeholder="At least 10 characters" /><Pressable style={styles.primary} disabled={busy} onPress={() => run((p: string) => onExport(p))}>{busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>Create encrypted backup</Text>}</Pressable><Text style={styles.dividerLabel}>RESTORE</Text><Field label="Encrypted backup text" value={backup} onChangeText={setBackup} multiline placeholder="Paste your NEXORA backup here" autoCapitalize="none" /><Pressable style={styles.secondary} disabled={busy} onPress={() => run((p: string, b: string) => onImport(b, p))}><Text style={styles.secondaryText}>Restore accounts</Text></Pressable><Pressable style={styles.secondary} onPress={async () => { const text = await Clipboard.getStringAsync(); setBackup(text); }}><Text style={styles.secondaryText}>Paste from clipboard</Text></Pressable></ScrollView></KeyboardAvoidingView>; }
function Field({ label, ...props }: any) { return <View style={styles.field}><Text style={styles.fieldLabel}>{label}</Text><TextInput {...props} style={[styles.input, props.multiline && styles.multiline]} placeholderTextColor="#68738a" /></View>; }

const styles = StyleSheet.create({ root: { flex: 1, backgroundColor: '#070A10' }, flex: { flex: 1 }, header: { paddingHorizontal: 20, paddingTop: 14, paddingBottom: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }, brand: { color: '#F4F7FB', fontSize: 23, fontWeight: '800', letterSpacing: 2 }, subtitle: { color: '#7F8A9D', fontSize: 12, marginTop: 3 }, headerButton: { width: 42, height: 42, borderRadius: 14, backgroundColor: '#111722', alignItems: 'center', justifyContent: 'center' }, headerIcon: { color: '#D8E0ED', fontSize: 21 }, homeIntro: { paddingHorizontal: 20, paddingVertical: 12, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }, sectionTitle: { color: '#F2F5FA', fontSize: 27, fontWeight: '700' }, sectionSub: { color: '#7E899C', marginTop: 4 }, addButton: { borderRadius: 12, paddingHorizontal: 14, paddingVertical: 10, backgroundColor: '#1A2434' }, addText: { color: '#9BC4FF', fontWeight: '700' }, list: { padding: 20, paddingTop: 8, gap: 14 }, accountCard: { backgroundColor: '#101620', borderRadius: 20, padding: 17, borderWidth: 1, borderColor: '#1B2635' }, accountTop: { flexDirection: 'row', alignItems: 'center' }, avatar: { width: 46, height: 46, borderRadius: 15, backgroundColor: '#1D2B40', alignItems: 'center', justifyContent: 'center' }, avatarText: { color: '#A9CAFF', fontWeight: '800' }, accountInfo: { flex: 1, marginLeft: 12 }, issuer: { color: '#F0F4FA', fontWeight: '700', fontSize: 16 }, accountName: { color: '#788498', marginTop: 3 }, more: { padding: 8 }, moreText: { color: '#6D788B', letterSpacing: 2 }, codeArea: { paddingVertical: 20 }, code: { color: '#FFFFFF', fontSize: 34, fontWeight: '800', letterSpacing: 3, fontVariant: ['tabular-nums'] }, copyHint: { color: '#69758A', fontSize: 11, marginTop: 5 }, timerRow: { flexDirection: 'row', alignItems: 'center', gap: 10 }, track: { flex: 1, height: 5, backgroundColor: '#202A38', borderRadius: 5, overflow: 'hidden' }, progress: { height: 5, backgroundColor: '#79AFFF', borderRadius: 5 }, timer: { color: '#8C98AA', fontSize: 12, width: 28, textAlign: 'right' }, cardActions: { marginTop: 14, paddingTop: 11, borderTopWidth: 1, borderTopColor: '#1A2432', flexDirection: 'row', justifyContent: 'flex-end', gap: 20 }, actionText: { color: '#9FC6FF', fontWeight: '700' }, deleteText: { color: '#E28B95', fontWeight: '700' }, empty: { margin: 20, marginTop: 50, alignItems: 'center', backgroundColor: '#0E141D', borderRadius: 22, padding: 28, borderWidth: 1, borderColor: '#1A2430' }, emptyIcon: { color: '#8DBBFF', fontSize: 38 }, emptyTitle: { color: '#F2F5FA', fontSize: 19, fontWeight: '700', marginTop: 14 }, emptyText: { color: '#7C8799', textAlign: 'center', lineHeight: 21, marginTop: 8, maxWidth: 320 }, primary: { marginTop: 22, backgroundColor: '#2D7DFF', minHeight: 54, borderRadius: 15, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 }, primarySmall: { marginTop: 20, backgroundColor: '#2D7DFF', minHeight: 48, borderRadius: 14, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 }, primaryText: { color: '#FFF', fontWeight: '800', fontSize: 15 }, secondary: { marginTop: 12, backgroundColor: '#121A26', minHeight: 52, borderRadius: 14, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20, borderWidth: 1, borderColor: '#243145' }, secondaryText: { color: '#B8C8DE', fontWeight: '700' }, subHeader: { paddingHorizontal: 20, paddingVertical: 12, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }, back: { color: '#9FC6FF', fontWeight: '700', width: 55 }, subHeaderTitle: { color: '#F1F5FA', fontSize: 18, fontWeight: '700' }, tabs: { margin: 20, marginBottom: 14, backgroundColor: '#111722', padding: 4, borderRadius: 14, flexDirection: 'row' }, tab: { flex: 1, paddingVertical: 11, borderRadius: 11, alignItems: 'center' }, tabActive: { backgroundColor: '#27364C' }, tabText: { color: '#748096', fontWeight: '700' }, tabTextActive: { color: '#DDE9FB' }, scannerWrap: { flex: 1, margin: 20, borderRadius: 22, overflow: 'hidden', backgroundColor: '#0F151E' }, camera: { flex: 1 }, scanFrame: { width: 240, height: 240, borderWidth: 2, borderColor: '#A6C8FF', borderRadius: 25, alignSelf: 'center', marginTop: '35%' }, permission: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 28 }, form: { padding: 20, paddingBottom: 40 }, field: { marginBottom: 16 }, fieldLabel: { color: '#A8B3C4', fontSize: 12, fontWeight: '700', marginBottom: 8, letterSpacing: .3 }, input: { minHeight: 52, borderRadius: 14, backgroundColor: '#101722', borderWidth: 1, borderColor: '#202C3C', color: '#F1F5FA', paddingHorizontal: 15, fontSize: 15 }, multiline: { minHeight: 150, textAlignVertical: 'top', paddingTop: 14 }, choiceRow: { flexDirection: 'row', gap: 8, marginBottom: 16 }, choice: { paddingHorizontal: 15, paddingVertical: 11, borderRadius: 12, backgroundColor: '#101722', borderWidth: 1, borderColor: '#202C3C' }, choiceActive: { backgroundColor: '#23334A', borderColor: '#5689C9' }, choiceText: { color: '#B9C5D7', fontWeight: '700' }, settings: { padding: 20, paddingBottom: 50 }, settingsSection: { color: '#6E7A8D', fontSize: 12, fontWeight: '800', letterSpacing: 1.1, marginTop: 12, marginBottom: 10 }, settingRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 17, borderBottomWidth: 1, borderBottomColor: '#141D29' }, settingButton: { paddingVertical: 17, borderBottomWidth: 1, borderBottomColor: '#141D29' }, settingButtonTitle: { color: '#E7EDF6', fontSize: 15, fontWeight: '700' }, settingButtonSub: { color: '#758196', marginTop: 4, lineHeight: 19 }, rowTitle: { color: '#E9EEF6', fontSize: 15, fontWeight: '700' }, rowSub: { color: '#778398', fontSize: 12, marginTop: 4, lineHeight: 18 }, footer: { color: '#5F6B7E', fontSize: 12, lineHeight: 18, marginTop: 30 }, infoBox: { backgroundColor: '#0E1723', borderRadius: 16, padding: 16, borderWidth: 1, borderColor: '#203048', marginBottom: 20 }, infoTitle: { color: '#B8D2F8', fontWeight: '800', marginBottom: 6 }, infoText: { color: '#7F8DA2', lineHeight: 19 }, dividerLabel: { color: '#677389', fontSize: 11, fontWeight: '800', letterSpacing: 1, marginTop: 28, marginBottom: 12 }, toast: { position: 'absolute', left: 30, right: 30, bottom: 24, backgroundColor: '#EAF2FF', borderRadius: 14, paddingVertical: 13, alignItems: 'center' }, toastText: { color: '#14243B', fontWeight: '800' }, splash: { flex: 1, backgroundColor: '#070A10', alignItems: 'center', justifyContent: 'center' }, splashLogo: { color: '#0A0E15', backgroundColor: '#A9CAFF', width: 76, height: 76, borderRadius: 24, textAlign: 'center', textAlignVertical: 'center', fontSize: 46, fontWeight: '900' }, splashTitle: { color: '#F4F7FB', fontSize: 30, fontWeight: '900', letterSpacing: 5, marginTop: 18 }, splashSub: { color: '#738095', marginTop: 6 }, onboard: { flex: 1, padding: 28, justifyContent: 'center' }, logoCircle: { width: 68, height: 68, borderRadius: 21, backgroundColor: '#A9CAFF', alignItems: 'center', justifyContent: 'center' }, logoText: { color: '#07101C', fontSize: 40, fontWeight: '900' }, hero: { color: '#F3F6FA', fontSize: 38, fontWeight: '800', lineHeight: 45, marginTop: 28 }, heroAccent: { color: '#86B7FF' }, onboardText: { color: '#7D899D', fontSize: 15, lineHeight: 23, marginTop: 15 }, securityCard: { backgroundColor: '#0E1621', borderWidth: 1, borderColor: '#1D2B3E', borderRadius: 18, padding: 18, marginTop: 26 }, cardTitle: { color: '#DDE8F7', fontWeight: '800' }, cardText: { color: '#78869A', lineHeight: 19, marginTop: 6 }, row: { flexDirection: 'row', alignItems: 'center', marginTop: 22 }, lock: { flex: 1, padding: 28, alignItems: 'center', justifyContent: 'center' }, lockTitle: { color: '#F4F7FB', fontSize: 24, fontWeight: '800', marginTop: 24 }, lockText: { color: '#7D899C', textAlign: 'center', lineHeight: 21, marginTop: 8, maxWidth: 320 }
});
