import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActivityIndicator, Alert, AppState, FlatList, Image, KeyboardAvoidingView, Platform,
  Pressable, SafeAreaView, ScrollView, Share, StyleSheet, Switch, Text, TextInput, View
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import * as DocumentPicker from 'expo-document-picker';
import * as FileSystem from 'expo-file-system/legacy';
import * as Sharing from 'expo-sharing';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as OTPAuth from 'otpauth';
import { createBackup, restoreBackup } from './src/backup';

export type Account = {
  id: string;
  issuer: string;
  account: string;
  algorithm: string;
  digits: number;
  period: number;
  createdAt: number;
  group: string;
  favorite: boolean;
  color: string;
  notes: string;
  lastViewed?: number;
  lastCopied?: number;
};

type Settings = {
  biometric: boolean;
  autoLock: boolean;
  hideCodes: boolean;
  revealOnTap: boolean;
  clipboardSeconds: number;
  privacyMask: boolean;
  sort: 'name' | 'recent';
};

const META_KEY = 'nexora.accounts.v2';
const SETTINGS_KEY = 'nexora.settings.v2';
const ONBOARDED_KEY = 'nexora.onboarded.v1';
const SECRET_PREFIX = 'nexora.secret.v1.';
const APP_ICON = require('./assets/images/icon.png');

const defaultSettings: Settings = {
  biometric: true,
  autoLock: true,
  hideCodes: false,
  revealOnTap: false,
  clipboardSeconds: 15,
  privacyMask: true,
  sort: 'name',
};

const uid = () => Crypto.randomUUID();
const secretKey = (id: string) => `${SECRET_PREFIX}${id}`;

async function readAccounts(): Promise<Account[]> {
  const raw = await AsyncStorage.getItem(META_KEY);
  if (!raw) {
    // Migrate the original v1 metadata shape if it exists.
    const old = await AsyncStorage.getItem('nexora.accounts.v1');
    if (!old) return [];
    const list = JSON.parse(old) as Array<any>;
    return list.map((a) => ({
      ...a,
      group: a.group || 'Personal',
      favorite: Boolean(a.favorite),
      color: a.color || '#79AFFF',
      notes: a.notes || '',
    }));
  }
  return JSON.parse(raw);
}

async function saveAccounts(accounts: Account[]) {
  await AsyncStorage.setItem(META_KEY, JSON.stringify(accounts));
}

async function getSecret(id: string) {
  return SecureStore.getItemAsync(secretKey(id));
}

async function saveSecret(id: string, secret: string) {
  await SecureStore.setItemAsync(secretKey(id), secret, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

async function deleteSecret(id: string) {
  await SecureStore.deleteItemAsync(secretKey(id));
}

function normalizeSecret(input: string) {
  return input.replace(/[\s-]/g, '').toUpperCase();
}

function parseManualInput(input: string) {
  const trimmed = input.trim();
  if (trimmed.toLowerCase().startsWith('otpauth://')) {
    if (!trimmed.toLowerCase().startsWith('otpauth://totp/')) {
      throw new Error('Only TOTP otpauth:// links are supported.');
    }
    const parsed = OTPAuth.URI.parse(trimmed);
    if (!(parsed instanceof OTPAuth.TOTP)) throw new Error('Unsupported OTP type.');
    if (!parsed.secret?.base32) throw new Error('The otpauth link has no secret.');
    return {
      issuer: (parsed.issuer || '').trim() || 'Unknown',
      account: (parsed.label || '').trim(),
      secret: normalizeSecret(parsed.secret.base32),
      algorithm: parsed.algorithm || 'SHA1',
      digits: parsed.digits || 6,
      period: parsed.period || 30,
    };
  }

  // Accept a common "secret=..." pasted query fragment too.
  const secretMatch = trimmed.match(/(?:^|[?&\s])secret=([A-Za-z2-7=\s-]+)/i);
  return { secret: normalizeSecret(secretMatch?.[1] || trimmed) };
}

function makeTotp(account: Account, secret: string) {
  return new OTPAuth.TOTP({
    issuer: account.issuer,
    label: account.account,
    secret,
    algorithm: account.algorithm,
    digits: account.digits,
    period: account.period,
  });
}

function getCode(account: Account, secret: string, now: number) {
  try {
    return makeTotp(account, secret).generate({ timestamp: now });
  } catch {
    return '------';
  }
}

function remaining(account: Account, now: number) {
  const elapsed = Math.floor(now / 1000) % account.period;
  return account.period - elapsed;
}

function initials(name: string) {
  const words = name.trim().split(/\s+/).filter(Boolean);
  return (words.length > 1 ? words[0][0] + words[1][0] : words[0]?.slice(0, 2) || 'NX').toUpperCase();
}

function validateBase32(secret: string) {
  return /^[A-Z2-7]+=*$/.test(secret) && secret.length >= 8;
}

function health(account: Account, secret: string, now: number) {
  return /^\d+$/.test(getCode(account, secret, now));
}

function makeAccount(data: {
  issuer: string;
  account: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
  group?: string;
  favorite?: boolean;
  color?: string;
  notes?: string;
}): Account {
  return {
    id: uid(),
    issuer: data.issuer.trim() || 'Unknown',
    account: data.account.trim(),
    algorithm: data.algorithm,
    digits: data.digits,
    period: data.period,
    createdAt: Date.now(),
    group: data.group?.trim() || 'Personal',
    favorite: Boolean(data.favorite),
    color: data.color || '#79AFFF',
    notes: data.notes || '',
  };
}

function accountKey(issuer: string, account: string) {
  return `${issuer}\u0000${account}`.trim().toLowerCase();
}

export default function App() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [onboarded, setOnboarded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [screen, setScreen] = useState<'home' | 'add' | 'settings' | 'edit' | 'backup' | 'security' | 'about'>('home');
  const [editing, setEditing] = useState<Account | null>(null);
  const [toast, setToast] = useState('');
  const [query, setQuery] = useState('');
  const [groupFilter, setGroupFilter] = useState('All');
  const [privacyMask, setPrivacyMask] = useState(false);
  const backgroundRef = useRef(false);
  const clipboardTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(''), 1800);
  }, []);

  const loadSecrets = useCallback(async (list: Account[]) => {
    const entries = await Promise.all(list.map(async (a) => [a.id, await getSecret(a.id)] as const));
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
      cancelLabel: 'Cancel',
      fallbackLabel: 'Use device passcode',
      disableDeviceFallback: false,
      biometricsSecurityLevel: 'strong',
    });
    return result.success;
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [a, sRaw, ob] = await Promise.all([
          readAccounts(),
          AsyncStorage.getItem(SETTINGS_KEY),
          AsyncStorage.getItem(ONBOARDED_KEY),
        ]);
        const s = sRaw ? { ...defaultSettings, ...JSON.parse(sRaw) } : defaultSettings;
        setAccounts(a);
        setSettings(s);
        setOnboarded(ob === '1');
        if (ob === '1' && s.biometric && a.length) setLocked(true);
        else await loadSecrets(a);
      } catch {
        Alert.alert('NEXORA', 'Could not load the secure vault.');
      } finally {
        setLoading(false);
      }
    })();
  }, [loadSecrets]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const sub = AppState.addEventListener('change', async (state) => {
      if (state !== 'active') {
        backgroundRef.current = true;
        if (settings.privacyMask) setPrivacyMask(true);
      }
      if (state === 'active' && backgroundRef.current) {
        backgroundRef.current = false;
        setPrivacyMask(false);
        if (settings.autoLock && settings.biometric && accounts.length) {
          setLocked(true);
          setSecrets({});
        }
      }
    });
    return () => sub.remove();
  }, [accounts.length, settings.autoLock, settings.biometric, settings.privacyMask]);

  const unlock = async () => {
    const ok = await authenticate();
    if (ok) {
      await loadSecrets(accounts);
      setLocked(false);
    } else {
      showToast('Authentication cancelled');
    }
  };

  const updateSettings = async (next: Settings) => {
    if (next.biometric && accounts.length) {
      const ok = await authenticate();
      if (!ok) {
        showToast('Biometric protection not enabled');
        return;
      }
    }
    setSettings(next);
    await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
  };

  const duplicateExists = (issuer: string, account: string, exceptId?: string) => {
    const normalized = accountKey(issuer, account);
    return accounts.some((a) => a.id !== exceptId && accountKey(a.issuer, a.account) === normalized);
  };

  const addAccount = async (data: {
    issuer: string;
    account: string;
    secret: string;
    algorithm: string;
    digits: number;
    period: number;
    group?: string;
    notes?: string;
    favorite?: boolean;
  }) => {
    const parsed = parseManualInput(data.secret);
    const secret = parsed.secret;
    const issuer = parsed.issuer ?? data.issuer;
    const account = parsed.account ?? data.account;
    const algorithm = parsed.algorithm ?? data.algorithm;
    const digits = parsed.digits ?? data.digits;
    const period = parsed.period ?? data.period;

    if (!validateBase32(secret)) throw new Error('Enter a valid Base32 secret or otpauth:// TOTP link.');
    if (!account?.trim()) throw new Error('Account name is required.');
    if (duplicateExists(issuer || 'Unknown', account)) {
      throw new Error('This authenticator account already exists in NEXORA.');
    }

    const accountObj = makeAccount({
      issuer: issuer || 'Unknown',
      account,
      secret,
      algorithm,
      digits,
      period,
      group: data.group,
      favorite: data.favorite,
      notes: data.notes,
    });

    const code = getCode(accountObj, secret, Date.now());
    if (!/^\d+$/.test(code)) throw new Error('The secret could not generate a valid TOTP code.');

    await saveSecret(accountObj.id, secret);
    const next = [...accounts, accountObj];
    await saveAccounts(next);
    setAccounts(next);
    setSecrets((v) => ({ ...v, [accountObj.id]: secret }));
    setScreen('home');
    showToast('Account added');
  };

  const editAccount = async (data: Partial<Account> & { secret?: string }) => {
    if (!editing) return;
    if (duplicateExists(data.issuer ?? editing.issuer, data.account ?? editing.account, editing.id)) {
      throw new Error('Another account with the same issuer and account already exists.');
    }

    let normalizedSecret = secrets[editing.id];
    if (data.secret) {
      const parsed = parseManualInput(data.secret);
      normalizedSecret = parsed.secret;
      if (!validateBase32(normalizedSecret)) throw new Error('Enter a valid Base32 secret or otpauth:// TOTP link.');
      await saveSecret(editing.id, normalizedSecret);
    }

    const nextAccount: Account = {
      ...editing,
      ...data,
      issuer: data.issuer?.trim() || editing.issuer,
      account: data.account?.trim() || editing.account,
      lastViewed: editing.lastViewed,
      lastCopied: editing.lastCopied,
    };

    const next = accounts.map((a) => (a.id === editing.id ? nextAccount : a));
    await saveAccounts(next);
    setAccounts(next);
    if (normalizedSecret) setSecrets((v) => ({ ...v, [editing.id]: normalizedSecret! }));
    setEditing(null);
    setScreen('home');
    showToast('Account updated');
  };

  const removeAccount = (account: Account) => {
    Alert.alert('Delete account?', `${account.issuer} • ${account.account}`, [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete',
        style: 'destructive',
        onPress: async () => {
          await deleteSecret(account.id);
          const next = accounts.filter((a) => a.id !== account.id);
          await saveAccounts(next);
          setAccounts(next);
          setSecrets((v) => {
            const n = { ...v };
            delete n[account.id];
            return n;
          });
          showToast('Account deleted');
        },
      },
    ]);
  };

  const copyCode = async (account: Account) => {
    const secret = secrets[account.id] || '';
    if (!secret) {
      showToast('Unlock NEXORA first');
      return;
    }
    const code = getCode(account, secret, now);
    await Clipboard.setStringAsync(code);

    const updated = { ...account, lastCopied: Date.now() };
    const next = accounts.map((a) => (a.id === account.id ? updated : a));
    setAccounts(next);
    await saveAccounts(next);

    if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);
    if (settings.clipboardSeconds > 0) {
      clipboardTimerRef.current = setTimeout(() => {
        void Clipboard.setStringAsync('');
      }, settings.clipboardSeconds * 1000);
    }
    showToast(`Code copied • clears in ${settings.clipboardSeconds}s`);
  };

  const touchAccount = async (account: Account) => {
    const updated = { ...account, lastViewed: Date.now() };
    const next = accounts.map((a) => (a.id === account.id ? updated : a));
    setAccounts(next);
    await saveAccounts(next);
  };

  const saveAccountPatch = async (account: Account) => {
    const next = accounts.map((a) => (a.id === account.id ? account : a));
    await saveAccounts(next);
    setAccounts(next);
  };

  const createEncryptedBackup = async (password: string, requireBiometric = false) => {
    if (password.length < 10) {
      throw new Error('Use at least 10 characters for the backup password.');
    }
    if (requireBiometric && !(await authenticate())) {
      throw new Error('Biometric authentication was cancelled.');
    }
    const payload = await Promise.all(accounts.map(async (a) => {
      const secret = await getSecret(a.id);
      if (!secret) throw new Error(`Could not read the secret for ${a.issuer}.`);
      return { ...a, secret };
    }));
    const backup = await createBackup(payload, password);
    const encrypted = JSON.stringify({
      ...JSON.parse(backup),
      exportNote: 'Password-protected NEXORA backup',
    });
    const fileUri = `${FileSystem.cacheDirectory}NEXORA-${new Date().toISOString().slice(0, 10)}.nxb`;
    await FileSystem.writeAsStringAsync(fileUri, encrypted);
    if (await Sharing.isAvailableAsync()) {
      await Sharing.shareAsync(fileUri, {
        mimeType: 'application/octet-stream',
        dialogTitle: 'Save or share encrypted NEXORA backup',
        UTI: 'public.data',
      });
    } else {
      await Share.share({ message: encrypted, title: 'NEXORA encrypted backup' });
    }
    showToast('Encrypted backup ready');
  };

  const [pendingBackupText, setPendingBackupText] = useState('');

  const applyImported = async (imported: any[], mode: 'new' | 'replace') => {
    const next = [...accounts];
    const nextSecrets = { ...secrets };
    const currentByKey = new Map(next.map((a) => [accountKey(a.issuer, a.account), a]));
    for (const item of imported) {
      const key = accountKey(item.issuer, item.account);
      const existing = currentByKey.get(key);

      if (existing) {
        if (mode === 'new') continue;
        const replacement: Account = {
          ...existing,
          issuer: item.issuer,
          account: item.account,
          algorithm: item.algorithm,
          digits: item.digits,
          period: item.period,
          group: item.group || existing.group,
          favorite: Boolean(item.favorite),
          color: item.color || existing.color,
          notes: item.notes || '',
        };
        const index = next.findIndex((a) => a.id === existing.id);
        next[index] = replacement;
        await saveSecret(existing.id, item.secret);
        nextSecrets[existing.id] = item.secret;
      } else {
        const a: Account = makeAccount({
          issuer: item.issuer,
          account: item.account,
          secret: item.secret,
          algorithm: item.algorithm,
          digits: item.digits,
          period: item.period,
          group: item.group,
          favorite: item.favorite,
          color: item.color,
          notes: item.notes,
        });
        await saveSecret(a.id, item.secret);
        next.push(a);
        nextSecrets[a.id] = item.secret;
        currentByKey.set(key, a);
      }
    }
    await saveAccounts(next);
    setAccounts(next);
    setSecrets(nextSecrets);
    setPendingBackupText('');
    setScreen('home');
    showToast('Backup restored');
  };

  if (loading) return <Splash />;
  if (privacyMask) return <PrivacyOverlay icon={APP_ICON} />;
  if (!onboarded) {
    return (
      <Onboarding
        onDone={async (useBiometric) => {
          const next = { ...settings, biometric: useBiometric };
          await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
          await AsyncStorage.setItem(ONBOARDED_KEY, '1');
          setSettings(next);
          setOnboarded(true);
        }}
      />
    );
  }
  if (locked) return <LockScreen onUnlock={unlock} />;

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      {screen === 'home' && (
        <Home
          accounts={accounts}
          secrets={secrets}
          now={now}
          settings={settings}
          query={query}
          setQuery={setQuery}
          groupFilter={groupFilter}
          setGroupFilter={setGroupFilter}
          onAdd={() => setScreen('add')}
          onCopy={copyCode}
          onEdit={(a: Account) => { setEditing(a); void touchAccount(a); setScreen('edit'); }}
          onDelete={removeAccount}
          onToggleFavorite={async (a: Account) => {
            await saveAccountPatch({ ...a, favorite: !a.favorite });
          }}
          onSettings={() => setScreen('settings')}
          onSecurity={() => setScreen('security')}
        />
      )}
      {screen === 'add' && <AddAccount onBack={() => setScreen('home')} onSave={addAccount} />}
      {screen === 'settings' && (
        <SettingsView
          settings={settings}
          accounts={accounts.length}
          onBack={() => setScreen('home')}
          onChange={updateSettings}
          onBackup={() => setScreen('backup')}
          onSecurity={() => setScreen('security')}
          onAbout={() => setScreen('about')}
          onLock={() => { setLocked(true); setSecrets({}); }}
        />
      )}
      {screen === 'security' && (
        <SecurityCenter
          settings={settings}
          accounts={accounts}
          secrets={secrets}
          now={now}
          onBack={() => setScreen('settings')}
          onLock={() => { setLocked(true); setSecrets({}); }}
          onBackup={() => setScreen('backup')}
        />
      )}
      {screen === 'edit' && editing && (
        <EditAccount
          account={editing}
          secret={secrets[editing.id] || ''}
          onBack={() => { setEditing(null); setScreen('home'); }}
          onSave={editAccount}
        />
      )}
      {screen === 'backup' && (
        <BackupView
          pendingBackupText={pendingBackupText}
          onSetPendingBackupText={setPendingBackupText}
          onBack={() => setScreen('security')}
          onExport={(password: string) => createEncryptedBackup(password, false)}
          onEmergencyExport={(password: string) => createEncryptedBackup(password, true)}
          onImport={async (text: string, password: string) => {
            const imported = await restoreBackup(text.trim(), password);
            const conflicts = imported.filter((item: any) =>
              accounts.some((a) => accountKey(a.issuer, a.account) === accountKey(item.issuer, item.account))
            ).length;
            if (conflicts) {
              Alert.alert(
                'Backup conflicts',
                `${imported.length} accounts found • ${conflicts} already exist.`,
                [
                  { text: 'Cancel', style: 'cancel' },
                  { text: 'Import new only', onPress: () => void applyImported(imported, 'new') },
                  { text: 'Replace duplicates', style: 'destructive', onPress: () => void applyImported(imported, 'replace') },
                ],
              );
            } else {
              await applyImported(imported, 'new');
            }
          }}
          onPickFile={async () => {
            try {
              const picked = await DocumentPicker.getDocumentAsync({
                type: ['application/octet-stream', 'application/json', 'text/plain'],
                copyToCacheDirectory: true,
                multiple: false,
              });
              if (!picked.canceled && picked.assets?.length) {
                const text = await FileSystem.readAsStringAsync(picked.assets[0].uri);
                setPendingBackupText(text);
                showToast('Backup file loaded');
              }
            } catch {
              showToast('Could not open backup file');
            }
          }}
        />
      )}
      {screen === 'about' && <AboutView onBack={() => setScreen('settings')} />}
      {toast ? <View style={styles.toast}><Text style={styles.toastText}>{toast}</Text></View> : null}
    </SafeAreaView>
  );
}

function Splash() {
  return (
    <View style={styles.splash}>
      <Image source={APP_ICON} style={styles.splashIcon} resizeMode="cover" />
      <Text style={styles.splashTitle}>NEXORA</Text>
      <Text style={styles.splashSub}>Secure authentication, offline.</Text>
      <ActivityIndicator style={{ marginTop: 28 }} />
    </View>
  );
}

function PrivacyOverlay({ icon }: { icon: any }) {
  return (
    <View style={styles.splash}>
      <Image source={icon} style={styles.brandIconLarge} />
      <Text style={styles.splashTitle}>NEXORA</Text>
      <Text style={styles.splashSub}>Privacy protected</Text>
    </View>
  );
}

function Onboarding({ onDone }: { onDone: (biometric: boolean) => void | Promise<void> }) {
  const [biometric, setBiometric] = useState(true);
  const [available, setAvailable] = useState(false);
  useEffect(() => {
    (async () => {
      const hardware = await LocalAuthentication.hasHardwareAsync();
      const enrolled = await LocalAuthentication.isEnrolledAsync();
      setAvailable(hardware && enrolled);
    })();
  }, []);
  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      <ScrollView contentContainerStyle={styles.onboard}>
        <Image source={APP_ICON} style={styles.brandIconLarge} />
        <Text style={styles.hero}>Your codes.<Text style={styles.heroAccent}> Your device.</Text></Text>
        <Text style={styles.onboardText}>
          NEXORA is an offline-first authenticator. Secrets stay on your device and TOTP codes do not require a NEXORA account or server.
        </Text>
        <View style={styles.securityCard}>
          <Text style={styles.cardTitle}>🔐 Private by design</Text>
          <Text style={styles.cardText}>SecureStore-backed secrets, biometric lock, encrypted backups and local Smart Vault organization.</Text>
        </View>
        {available && (
          <View style={styles.settingRow}>
            <View style={{ flex: 1 }}>
              <Text style={styles.rowTitle}>Protect with biometrics</Text>
              <Text style={styles.rowSub}>Fingerprint, face or device passcode</Text>
            </View>
            <Switch value={biometric} onValueChange={setBiometric} />
          </View>
        )}
        <Pressable style={styles.primary} onPress={() => void onDone(available && biometric)}>
          <Text style={styles.primaryText}>Get started</Text>
        </Pressable>
      </ScrollView>
    </SafeAreaView>
  );
}

function LockScreen({ onUnlock }: { onUnlock: () => void | Promise<void> }) {
  return (
    <SafeAreaView style={styles.root}>
      <StatusBar style="light" />
      <View style={styles.lock}>
        <Image source={APP_ICON} style={styles.brandIconLarge} />
        <Text style={styles.lockTitle}>NEXORA is locked</Text>
        <Text style={styles.lockText}>Authenticate to access your authenticator vault.</Text>
        <Pressable style={styles.primary} onPress={() => void onUnlock()}>
          <Text style={styles.primaryText}>Unlock</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

function Home(props: any) {
  const groups: string[] = [
    'All',
    ...Array.from(
      new Set<string>(
        props.accounts.map((a: Account) => String(a.group || 'Personal'))
      )
    ),
  ];
  const filtered = props.accounts
    .filter((a: Account) => !props.query || `${a.issuer} ${a.account} ${a.group}`.toLowerCase().includes(props.query.toLowerCase()))
    .filter((a: Account) => props.groupFilter === 'All' || a.group === props.groupFilter)
    .sort((a: Account, b: Account) => props.settings.sort === 'recent'
      ? (b.lastViewed || b.createdAt) - (a.lastViewed || a.createdAt)
      : `${a.issuer} ${a.account}`.localeCompare(`${b.issuer} ${b.account}`));
  return (
    <View style={styles.flex}>
      <View style={styles.header}>
        <View>
          <Text style={styles.brand}>NEXORA</Text>
          <Text style={styles.subtitle}>Smart Vault • {props.accounts.length} accounts</Text>
        </View>
        <View style={styles.headerActions}>
          <Pressable style={styles.headerButton} onPress={props.onSecurity}><Text style={styles.headerIcon}>🛡</Text></Pressable>
          <Pressable style={styles.headerButton} onPress={props.onSettings}><Text style={styles.headerIcon}>⚙</Text></Pressable>
        </View>
      </View>
      <View style={styles.searchWrap}>
        <Text style={styles.searchIcon}>⌕</Text>
        <TextInput
          style={styles.searchInput}
          value={props.query}
          onChangeText={props.setQuery}
          placeholder="Search accounts"
          placeholderTextColor="#68738a"
        />
      </View>
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.chips}>
        {groups.map((g) => (
          <Pressable key={g} style={[styles.chip, props.groupFilter === g && styles.chipActive]} onPress={() => props.setGroupFilter(g)}>
            <Text style={[styles.chipText, props.groupFilter === g && styles.chipTextActive]}>{g === 'All' ? '🛡 All' : `🏷 ${g}`}</Text>
          </Pressable>
        ))}
      </ScrollView>

      {filtered.length === 0 ? (
        <View style={styles.empty}>
          <Image source={APP_ICON} style={styles.emptyIconImage} />
          <Text style={styles.emptyTitle}>{props.accounts.length ? 'No matching accounts' : 'No accounts yet'}</Text>
          <Text style={styles.emptyText}>Scan a QR code or enter a Base32 secret to add your first authenticator.</Text>
          <Pressable style={styles.primarySmall} onPress={props.onAdd}><Text style={styles.primaryText}>Add account</Text></Pressable>
        </View>
      ) : (
        <FlatList
          data={filtered}
          keyExtractor={(a: Account) => a.id}
          contentContainerStyle={styles.list}
          renderItem={({ item }: { item: Account }) => (
            <AccountCard
              account={item}
              secret={props.secrets[item.id]}
              now={props.now}
              settings={props.settings}
              onCopy={() => props.onCopy(item)}
              onEdit={() => props.onEdit(item)}
              onDelete={() => props.onDelete(item)}
              onToggleFavorite={() => props.onToggleFavorite(item)}
            />
          )}
        />
      )}
      <Pressable style={styles.floatingAdd} onPress={props.onAdd}><Text style={styles.floatingAddText}>＋</Text></Pressable>
    </View>
  );
}

function AccountCard({ account, secret, now, settings, onCopy, onEdit, onDelete, onToggleFavorite }: any) {
  const code = secret ? getCode(account, secret, now) : '------';
  const left = remaining(account, now);
  const progress = Math.max(0, Math.min(1, left / account.period));
  const isHealthy = secret ? health(account, secret, now) : false;
  const masked = settings.hideCodes || (settings.revealOnTap && !settings._reveal?.[account.id]);

  return (
    <View style={styles.accountCard}>
      <View style={styles.accountTop}>
        <View style={[styles.avatar, { borderColor: account.color }]}>
          <Text style={styles.avatarText}>{initials(account.issuer)}</Text>
        </View>
        <View style={styles.accountInfo}>
          <Text style={styles.issuer}>{account.issuer}</Text>
          <Text style={styles.accountName} numberOfLines={1}>{account.account}</Text>
          <Text style={styles.groupLabel}>{account.group || 'Personal'} • {isHealthy ? 'Healthy' : 'Check secret'}</Text>
        </View>
        <Pressable onPress={onToggleFavorite} style={styles.favoriteButton}>
          <Text style={styles.favoriteText}>{account.favorite ? '★' : '☆'}</Text>
        </Pressable>
      </View>

      <Pressable
        onPress={() => {
          if (settings.revealOnTap && settings.hideCodes === false) {
            // Reveal-on-tap mode is handled visually by tapping to copy.
          }
          void onCopy();
        }}
        style={styles.codeArea}
      >
        <Text style={styles.code}>{masked ? '••••••' : `${code.slice(0, 3)} ${code.slice(3)}`}</Text>
        <Text style={styles.copyHint}>Tap to copy • {left}s</Text>
      </Pressable>

      <View style={styles.timerRow}>
        <View style={styles.track}><View style={[styles.progress, { width: `${progress * 100}%`, backgroundColor: account.color }]} /></View>
        <Text style={styles.timer}>{left}s</Text>
      </View>

      <View style={styles.cardActions}>
        <Pressable onPress={onEdit}><Text style={styles.actionText}>Edit</Text></Pressable>
        <Pressable onPress={onDelete}><Text style={styles.deleteText}>Delete</Text></Pressable>
      </View>
    </View>
  );
}

function AddAccount({ onBack, onSave }: any) {
  const [mode, setMode] = useState<'scan' | 'manual'>('scan');
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);
  const [issuer, setIssuer] = useState('');
  const [account, setAccount] = useState('');
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('SHA1');
  const [digits, setDigits] = useState('6');
  const [period, setPeriod] = useState('30');
  const [group, setGroup] = useState('Personal');
  const [favorite, setFavorite] = useState(false);
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);

  const save = async () => {
    try {
      setSaving(true);
      await onSave({ issuer, account, secret, algorithm, digits: Number(digits), period: Number(period), group, favorite, notes });
    } catch (e: any) {
      Alert.alert('Could not add account', e.message || 'Invalid account.');
    } finally {
      setSaving(false);
    }
  };

  const scan = ({ data }: any) => {
    if (scanned) return;
    setScanned(true);
    try {
      const parsed = parseManualInput(data);
      if (parsed.issuer) setIssuer(parsed.issuer);
      if (parsed.account) setAccount(parsed.account);
      setSecret(data);
      if (parsed.algorithm) setAlgorithm(parsed.algorithm);
      if (parsed.digits) setDigits(String(parsed.digits));
      if (parsed.period) setPeriod(String(parsed.period));
      setMode('manual');
      Alert.alert('QR detected', `${parsed.issuer || 'Unknown'}\n${parsed.account || 'Account detected'}\n\nReview the details before saving.`);
    } catch (e: any) {
      Alert.alert('Unsupported QR code', e.message || 'Invalid QR.');
      setScanned(false);
    }
  };

  return (
    <View style={styles.flex}>
      <View style={styles.subHeader}>
        <Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable>
        <Text style={styles.subHeaderTitle}>Add account</Text>
        <View style={{ width: 55 }} />
      </View>
      <View style={styles.tabs}>
        <Pressable style={[styles.tab, mode === 'scan' && styles.tabActive]} onPress={() => setMode('scan')}><Text style={[styles.tabText, mode === 'scan' && styles.tabTextActive]}>Scan QR</Text></Pressable>
        <Pressable style={[styles.tab, mode === 'manual' && styles.tabActive]} onPress={() => setMode('manual')}><Text style={[styles.tabText, mode === 'manual' && styles.tabTextActive]}>Manual</Text></Pressable>
      </View>

      {mode === 'scan' ? (
        <View style={styles.scannerWrap}>
          {!permission?.granted ? (
            <View style={styles.permission}>
              <Image source={APP_ICON} style={styles.emptyIconImage} />
              <Text style={styles.emptyTitle}>Camera access</Text>
              <Text style={styles.emptyText}>NEXORA uses the camera only to read TOTP authenticator QR codes.</Text>
              <Pressable style={styles.primarySmall} onPress={requestPermission}><Text style={styles.primaryText}>Allow camera</Text></Pressable>
            </View>
          ) : (
            <CameraView
              style={styles.camera}
              facing="back"
              barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
              onBarcodeScanned={scan}
            >
              <View style={styles.scanFrame} />
            </CameraView>
          )}
        </View>
      ) : (
        <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
          <ScrollView contentContainerStyle={styles.form}>
            <Field label="Issuer / service" value={issuer} onChangeText={setIssuer} placeholder="e.g. GitHub" />
            <Field label="Account" value={account} onChangeText={setAccount} placeholder="e.g. you@example.com" autoCapitalize="none" />
            <Field label="Secret / otpauth URI" value={secret} onChangeText={setSecret} placeholder="Base32 secret or otpauth://totp/..." autoCapitalize="characters" secureTextEntry />
            <Text style={styles.helper}>Supports Base32, spaces/hyphens, and complete otpauth:// TOTP links.</Text>

            <Text style={styles.fieldLabel}>Algorithm</Text>
            <View style={styles.choiceRow}>{['SHA1', 'SHA256', 'SHA512'].map((v) => <Pressable key={v} style={[styles.choice, algorithm === v && styles.choiceActive]} onPress={() => setAlgorithm(v)}><Text style={styles.choiceText}>{v}</Text></Pressable>)}</View>

            <Text style={styles.fieldLabel}>Digits</Text>
            <View style={styles.choiceRow}>{['6', '8'].map((v) => <Pressable key={v} style={[styles.choice, digits === v && styles.choiceActive]} onPress={() => setDigits(v)}><Text style={styles.choiceText}>{v}</Text></Pressable>)}</View>

            <Field label="Period (seconds)" value={period} onChangeText={setPeriod} keyboardType="number-pad" />
            <Field label="Group" value={group} onChangeText={setGroup} placeholder="Personal / Work" />
            <Field label="Notes (optional)" value={notes} onChangeText={setNotes} placeholder="Private local note" multiline />
            <View style={styles.settingRow}>
              <View style={{ flex: 1 }}><Text style={styles.rowTitle}>Favorite</Text><Text style={styles.rowSub}>Show this account in your preferred vault views.</Text></View>
              <Switch value={favorite} onValueChange={setFavorite} />
            </View>

            <Pressable style={styles.primary} onPress={() => void save()} disabled={saving}>
              {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>Validate & add account</Text>}
            </Pressable>
          </ScrollView>
        </KeyboardAvoidingView>
      )}
    </View>
  );
}

function EditAccount({ account, secret, onBack, onSave }: any) {
  const [issuer, setIssuer] = useState(account.issuer);
  const [name, setName] = useState(account.account);
  const [newSecret, setNewSecret] = useState('');
  const [group, setGroup] = useState(account.group || 'Personal');
  const [favorite, setFavorite] = useState(Boolean(account.favorite));
  const [notes, setNotes] = useState(account.notes || '');
  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <View style={styles.subHeader}>
        <Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable>
        <Text style={styles.subHeaderTitle}>Edit account</Text>
        <View style={{ width: 55 }} />
      </View>
      <ScrollView contentContainerStyle={styles.form}>
        <Field label="Issuer / service" value={issuer} onChangeText={setIssuer} />
        <Field label="Account" value={name} onChangeText={setName} autoCapitalize="none" />
        <Field label="Replace secret (optional)" value={newSecret} onChangeText={setNewSecret} placeholder="Base32 or otpauth:// TOTP link" autoCapitalize="characters" secureTextEntry />
        <Field label="Group" value={group} onChangeText={setGroup} />
        <Field label="Notes" value={notes} onChangeText={setNotes} multiline />
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>Secret protection</Text>
          <Text style={styles.infoText}>The current secret is stored in the device secure store and is never shown in full here.</Text>
        </View>
        <View style={styles.settingRow}>
          <View style={{ flex: 1 }}><Text style={styles.rowTitle}>Favorite</Text><Text style={styles.rowSub}>Pin this account in your Smart Vault.</Text></View>
          <Switch value={favorite} onValueChange={setFavorite} />
        </View>
        <Pressable style={styles.primary} onPress={() => void onSave({ issuer, account: name, secret: newSecret || undefined, group, favorite, notes })}>
          <Text style={styles.primaryText}>Save changes</Text>
        </Pressable>
        <Text style={styles.miniMeta}>{account.algorithm} • {account.digits} digits • {account.period}s</Text>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

function SecurityCenter({ settings, accounts, secrets, now, onBack, onLock, onBackup }: any) {
  const healthy = accounts.filter((a: Account) => secrets[a.id] && health(a, secrets[a.id], now)).length;
  const strong = [
    settings.biometric,
    settings.autoLock,
    settings.privacyMask,
    accounts.length === healthy,
  ].filter(Boolean).length;
  return (
    <View style={styles.flex}>
      <View style={styles.subHeader}>
        <Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable>
        <Text style={styles.subHeaderTitle}>Security Center</Text>
        <View style={{ width: 55 }} />
      </View>
      <ScrollView contentContainerStyle={styles.settings}>
        <View style={styles.securityHero}>
          <Image source={APP_ICON} style={styles.brandIcon} />
          <View><Text style={styles.securityScore}>{strong >= 4 ? 'Strong' : strong >= 2 ? 'Good' : 'Basic'}</Text><Text style={styles.rowSub}>{strong}/4 protection checks enabled</Text></View>
        </View>
        <Text style={styles.settingsSection}>Protection</Text>
        <SecurityCheck title="Biometric lock" ok={settings.biometric} subtitle="Require authentication to open the vault" />
        <SecurityCheck title="Auto-lock" ok={settings.autoLock} subtitle="Clear in-memory secrets when backgrounded" />
        <SecurityCheck title="Privacy mask" ok={settings.privacyMask} subtitle="Hide vault content when the app leaves the foreground" />
        <SecurityCheck title="Account health" ok={accounts.length === healthy} subtitle={`${healthy}/${accounts.length} accounts currently generate a valid code`} />
        <Text style={styles.settingsSection}>Actions</Text>
        <Pressable style={styles.settingButton} onPress={onBackup}><Text style={styles.settingButtonTitle}>Encrypted backup & restore</Text><Text style={styles.settingButtonSub}>Password-protected local backup files.</Text></Pressable>
        <Pressable style={styles.settingButton} onPress={onLock}><Text style={styles.settingButtonTitle}>Emergency lock</Text><Text style={styles.settingButtonSub}>Immediately clear loaded secrets and lock NEXORA.</Text></Pressable>
        <Text style={styles.footer}>NEXORA generates normal TOTP codes locally. No server is required for the authenticator vault.</Text>
      </ScrollView>
    </View>
  );
}

function SecurityCheck({ title, ok, subtitle }: { title: string; ok: boolean; subtitle: string }) {
  return (
    <View style={styles.checkRow}>
      <Text style={styles.checkIcon}>{ok ? '✓' : '!'}</Text>
      <View style={{ flex: 1 }}><Text style={styles.rowTitle}>{title}</Text><Text style={styles.rowSub}>{subtitle}</Text></View>
      <Text style={[styles.checkStatus, ok ? styles.checkOk : styles.checkWarn]}>{ok ? 'ON' : 'CHECK'}</Text>
    </View>
  );
}

function SettingsView({ settings, accounts, onBack, onChange, onBackup, onSecurity, onAbout, onLock }: any) {
  const clipboardOptions = [0, 5, 15, 30];
  return (
    <View style={styles.flex}>
      <View style={styles.subHeader}>
        <Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable>
        <Text style={styles.subHeaderTitle}>Settings</Text>
        <View style={{ width: 55 }} />
      </View>
      <ScrollView contentContainerStyle={styles.settings}>
        <Text style={styles.settingsSection}>Security</Text>
        <SettingRow title="Biometric lock" subtitle="Require authentication when opening NEXORA" value={settings.biometric} onValueChange={(v: boolean) => void onChange({ ...settings, biometric: v })} />
        <SettingRow title="Auto-lock" subtitle="Lock when NEXORA leaves the foreground" value={settings.autoLock} onValueChange={(v: boolean) => void onChange({ ...settings, autoLock: v })} />
        <SettingRow title="Privacy mask" subtitle="Show a privacy screen while NEXORA is not active" value={settings.privacyMask} onValueChange={(v: boolean) => void onChange({ ...settings, privacyMask: v })} />
        <SettingRow title="Hide codes" subtitle="Mask OTPs in the Smart Vault" value={settings.hideCodes} onValueChange={(v: boolean) => void onChange({ ...settings, hideCodes: v })} />

        <Text style={styles.settingsSection}>Clipboard</Text>
        <Text style={styles.rowSub}>Clear copied OTPs from the app clipboard after:</Text>
        <View style={styles.choiceRow}>{clipboardOptions.map((seconds) => <Pressable key={seconds} style={[styles.choice, settings.clipboardSeconds === seconds && styles.choiceActive]} onPress={() => void onChange({ ...settings, clipboardSeconds: seconds })}><Text style={styles.choiceText}>{seconds === 0 ? 'Off' : `${seconds}s`}</Text></Pressable>)}</View>

        <Text style={styles.settingsSection}>Vault</Text>
        <View style={styles.choiceRow}>
          <Pressable style={[styles.choice, settings.sort === 'name' && styles.choiceActive]} onPress={() => void onChange({ ...settings, sort: 'name' })}><Text style={styles.choiceText}>A–Z</Text></Pressable>
          <Pressable style={[styles.choice, settings.sort === 'recent' && styles.choiceActive]} onPress={() => void onChange({ ...settings, sort: 'recent' })}><Text style={styles.choiceText}>Recent</Text></Pressable>
        </View>
        <Pressable style={styles.settingButton} onPress={onBackup}><Text style={styles.settingButtonTitle}>Encrypted backup & restore</Text><Text style={styles.settingButtonSub}>Export or import your accounts as an encrypted file.</Text></Pressable>
        <Pressable style={styles.settingButton} onPress={onSecurity}><Text style={styles.settingButtonTitle}>Security Center</Text><Text style={styles.settingButtonSub}>Review NEXORA's local security posture.</Text></Pressable>
        <Pressable style={styles.settingButton} onPress={onLock}><Text style={styles.settingButtonTitle}>Lock now</Text><Text style={styles.settingButtonSub}>{accounts} accounts protected on this device.</Text></Pressable>

        <Text style={styles.settingsSection}>Diagnostics</Text>
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>Device time</Text>
          <Text style={styles.infoText}>{new Date().toLocaleString()}{'\n'}TOTP uses your device clock. For mismatched codes, verify Automatic date & time is enabled in Android system settings.</Text>
        </View>
        <Pressable style={styles.settingButton} onPress={onAbout}><Text style={styles.settingButtonTitle}>About NEXORA</Text><Text style={styles.settingButtonSub}>Version, privacy, transparency and components.</Text></Pressable>
      </ScrollView>
    </View>
  );
}

function SettingRow({ title, subtitle, value, onValueChange }: any) {
  return (
    <View style={styles.settingRow}>
      <View style={{ flex: 1 }}><Text style={styles.rowTitle}>{title}</Text><Text style={styles.rowSub}>{subtitle}</Text></View>
      <Switch value={value} onValueChange={onValueChange} />
    </View>
  );
}

function BackupView({ pendingBackupText, onSetPendingBackupText, onBack, onExport, onEmergencyExport, onImport, onPickFile }: any) {
  const [password, setPassword] = useState('');
  const [backup, setBackup] = useState(pendingBackupText || '');
  const [busy, setBusy] = useState(false);

  useEffect(() => setBackup(pendingBackupText || ''), [pendingBackupText]);

  const run = async (fn: () => Promise<void>) => {
    try {
      setBusy(true);
      await fn();
      setPassword('');
    } catch (e: any) {
      Alert.alert('Backup error', e.message || 'Could not complete backup operation.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <View style={styles.subHeader}>
        <Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable>
        <Text style={styles.subHeaderTitle}>Backup & restore</Text>
        <View style={{ width: 55 }} />
      </View>
      <ScrollView contentContainerStyle={styles.form}>
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>Encrypted backup</Text>
          <Text style={styles.infoText}>Backups contain authenticator secrets. Keep the password separate from the backup file.</Text>
        </View>

        <Field label="Backup password" value={password} onChangeText={setPassword} secureTextEntry placeholder="At least 10 characters" />
        <Pressable style={styles.primary} disabled={busy} onPress={() => void run(() => onExport(password))}>
          {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>Create encrypted backup</Text>}
        </Pressable>

        <Pressable style={styles.secondary} disabled={busy} onPress={() => void run(() => onEmergencyExport(password))}>
          <Text style={styles.secondaryText}>Emergency export • biometric required</Text>
        </Pressable>

        <Text style={styles.dividerLabel}>RESTORE</Text>
        <Pressable style={styles.secondary} onPress={onPickFile}><Text style={styles.secondaryText}>Import backup file</Text></Pressable>
        <Field label="Encrypted backup text" value={backup} onChangeText={(v: string) => { setBackup(v); onSetPendingBackupText(v); }} multiline placeholder="Paste a NEXORA backup here" autoCapitalize="none" />
        <Pressable style={styles.secondary} disabled={busy || !backup.trim()} onPress={() => void run(async () => onImport(backup, password))}><Text style={styles.secondaryText}>Restore accounts</Text></Pressable>
        <Pressable style={styles.secondary} onPress={async () => { const text = await Clipboard.getStringAsync(); setBackup(text); onSetPendingBackupText(text); }}><Text style={styles.secondaryText}>Paste from clipboard</Text></Pressable>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

function AboutView({ onBack }: { onBack: () => void }) {
  return (
    <View style={styles.flex}>
      <View style={styles.subHeader}>
        <Pressable onPress={onBack}><Text style={styles.back}>‹ Back</Text></Pressable>
        <Text style={styles.subHeaderTitle}>About NEXORA</Text>
        <View style={{ width: 55 }} />
      </View>
      <ScrollView contentContainerStyle={styles.settings}>
        <View style={styles.aboutHero}>
          <Image source={APP_ICON} style={styles.brandIconLarge} />
          <Text style={styles.heroSmall}>NEXORA</Text>
          <Text style={styles.rowSub}>Version 1.1.0 • Offline authenticator</Text>
        </View>
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>Privacy</Text>
          <Text style={styles.infoText}>No NEXORA account is required for normal authentication. Secrets are kept in secure local storage and codes are generated on-device.</Text>
        </View>
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>Transparency</Text>
          <Text style={styles.infoText}>NEXORA uses Expo, React Native, SecureStore, OTPAuth, AsyncStorage and audited cryptographic primitives from the project dependencies.</Text>
        </View>
        <Text style={styles.footer}>NEXORA is an authenticator application, not a password manager or identity provider. Protect your backup password and your device.</Text>
      </ScrollView>
    </View>
  );
}

function Field({ label, ...props }: any) {
  return (
    <View style={styles.field}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput {...props} style={[styles.input, props.multiline && styles.multiline]} placeholderTextColor="#68738a" />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#070A10' },
  flex: { flex: 1 },
  header: { paddingHorizontal: 20, paddingTop: 14, paddingBottom: 14, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  headerActions: { flexDirection: 'row', gap: 8 },
  brand: { color: '#F4F7FB', fontSize: 23, fontWeight: '800', letterSpacing: 2 },
  subtitle: { color: '#7F8A9D', fontSize: 12, marginTop: 3 },
  headerButton: { width: 42, height: 42, borderRadius: 14, backgroundColor: '#111722', alignItems: 'center', justifyContent: 'center' },
  headerIcon: { color: '#D8E0ED', fontSize: 18 },
  searchWrap: { marginHorizontal: 20, marginTop: 2, backgroundColor: '#101722', borderWidth: 1, borderColor: '#202C3C', borderRadius: 15, flexDirection: 'row', alignItems: 'center', paddingHorizontal: 14 },
  searchIcon: { color: '#88A4C8', fontSize: 24 },
  searchInput: { flex: 1, minHeight: 50, color: '#F1F5FA', paddingHorizontal: 8, fontSize: 15 },
  chips: { paddingHorizontal: 20, paddingVertical: 12, gap: 8 },
  chip: { backgroundColor: '#101722', borderWidth: 1, borderColor: '#202C3C', borderRadius: 14, paddingHorizontal: 13, paddingVertical: 8 },
  chipActive: { backgroundColor: '#23334A', borderColor: '#5689C9' },
  chipText: { color: '#7E8AA0', fontWeight: '700', fontSize: 12 },
  chipTextActive: { color: '#DDE9FB' },
  list: { paddingHorizontal: 20, paddingBottom: 110, gap: 14 },
  accountCard: { backgroundColor: '#101620', borderRadius: 20, padding: 17, borderWidth: 1, borderColor: '#1B2635' },
  accountTop: { flexDirection: 'row', alignItems: 'center' },
  avatar: { width: 46, height: 46, borderRadius: 15, backgroundColor: '#1D2B40', alignItems: 'center', justifyContent: 'center', borderWidth: 2 },
  avatarText: { color: '#A9CAFF', fontWeight: '800' },
  accountInfo: { flex: 1, marginLeft: 12 },
  issuer: { color: '#F0F4FA', fontWeight: '700', fontSize: 16 },
  accountName: { color: '#788498', marginTop: 3 },
  groupLabel: { color: '#53637A', fontSize: 11, marginTop: 4 },
  favoriteButton: { padding: 8 },
  favoriteText: { color: '#8DBBFF', fontSize: 24 },
  codeArea: { paddingVertical: 18 },
  code: { color: '#FFFFFF', fontSize: 34, fontWeight: '800', letterSpacing: 3, fontVariant: ['tabular-nums'] },
  copyHint: { color: '#69758A', fontSize: 11, marginTop: 5 },
  timerRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  track: { flex: 1, height: 5, backgroundColor: '#202A38', borderRadius: 5, overflow: 'hidden' },
  progress: { height: 5, borderRadius: 5 },
  timer: { color: '#8C98AA', fontSize: 12, width: 28, textAlign: 'right' },
  cardActions: { marginTop: 14, paddingTop: 11, borderTopWidth: 1, borderTopColor: '#1A2432', flexDirection: 'row', justifyContent: 'flex-end', gap: 20 },
  actionText: { color: '#9FC6FF', fontWeight: '700' },
  deleteText: { color: '#E28B95', fontWeight: '700' },
  floatingAdd: { position: 'absolute', right: 22, bottom: 24, width: 58, height: 58, borderRadius: 29, backgroundColor: '#2D7DFF', alignItems: 'center', justifyContent: 'center', elevation: 10 },
  floatingAddText: { color: '#fff', fontSize: 30, marginTop: -3 },
  empty: { margin: 20, marginTop: 40, alignItems: 'center', backgroundColor: '#0E141D', borderRadius: 22, padding: 28, borderWidth: 1, borderColor: '#1A2430' },
  emptyIconImage: { width: 72, height: 72, borderRadius: 18, marginBottom: 10 },
  emptyTitle: { color: '#F2F5FA', fontSize: 19, fontWeight: '700', marginTop: 4 },
  emptyText: { color: '#7C8799', textAlign: 'center', lineHeight: 21, marginTop: 8, maxWidth: 320 },
  primary: { marginTop: 22, backgroundColor: '#2D7DFF', minHeight: 54, borderRadius: 15, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 },
  primarySmall: { marginTop: 20, backgroundColor: '#2D7DFF', minHeight: 48, borderRadius: 14, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 },
  primaryText: { color: '#FFF', fontWeight: '800', fontSize: 15 },
  secondary: { marginTop: 12, backgroundColor: '#121A26', minHeight: 52, borderRadius: 14, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20, borderWidth: 1, borderColor: '#243145' },
  secondaryText: { color: '#B8C8DE', fontWeight: '700' },
  subHeader: { paddingHorizontal: 20, paddingVertical: 12, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  back: { color: '#9FC6FF', fontWeight: '700', width: 55 },
  subHeaderTitle: { color: '#F1F5FA', fontSize: 18, fontWeight: '700' },
  tabs: { margin: 20, marginBottom: 14, backgroundColor: '#111722', padding: 4, borderRadius: 14, flexDirection: 'row' },
  tab: { flex: 1, paddingVertical: 11, borderRadius: 11, alignItems: 'center' },
  tabActive: { backgroundColor: '#27364C' },
  tabText: { color: '#748096', fontWeight: '700' },
  tabTextActive: { color: '#DDE9FB' },
  scannerWrap: { flex: 1, margin: 20, borderRadius: 22, overflow: 'hidden', backgroundColor: '#0F151E' },
  camera: { flex: 1 },
  scanFrame: { width: 240, height: 240, borderWidth: 2, borderColor: '#A6C8FF', borderRadius: 25, alignSelf: 'center', marginTop: '35%' },
  permission: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 28 },
  form: { padding: 20, paddingBottom: 50 },
  field: { marginBottom: 16 },
  fieldLabel: { color: '#A8B3C4', fontSize: 12, fontWeight: '700', marginBottom: 8, letterSpacing: .3 },
  input: { minHeight: 52, borderRadius: 14, backgroundColor: '#101722', borderWidth: 1, borderColor: '#202C3C', color: '#F1F5FA', paddingHorizontal: 15, fontSize: 15 },
  multiline: { minHeight: 120, textAlignVertical: 'top', paddingTop: 14 },
  helper: { color: '#617087', fontSize: 11, lineHeight: 17, marginTop: -6, marginBottom: 14 },
  choiceRow: { flexDirection: 'row', gap: 8, marginTop: 8, marginBottom: 16, flexWrap: 'wrap' },
  choice: { paddingHorizontal: 15, paddingVertical: 11, borderRadius: 12, backgroundColor: '#101722', borderWidth: 1, borderColor: '#202C3C' },
  choiceActive: { backgroundColor: '#23334A', borderColor: '#5689C9' },
  choiceText: { color: '#B9C5D7', fontWeight: '700' },
  settings: { padding: 20, paddingBottom: 60 },
  settingsSection: { color: '#6E7A8D', fontSize: 12, fontWeight: '800', letterSpacing: 1.1, marginTop: 16, marginBottom: 10 },
  settingRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 17, borderBottomWidth: 1, borderBottomColor: '#141D29' },
  settingButton: { paddingVertical: 17, borderBottomWidth: 1, borderBottomColor: '#141D29' },
  settingButtonTitle: { color: '#E7EDF6', fontSize: 15, fontWeight: '700' },
  settingButtonSub: { color: '#758196', marginTop: 4, lineHeight: 19 },
  rowTitle: { color: '#E9EEF6', fontSize: 15, fontWeight: '700' },
  rowSub: { color: '#778398', fontSize: 12, marginTop: 4, lineHeight: 18 },
  footer: { color: '#5F6B7E', fontSize: 12, lineHeight: 18, marginTop: 30 },
  infoBox: { backgroundColor: '#0E1723', borderRadius: 16, padding: 16, borderWidth: 1, borderColor: '#203048', marginBottom: 20 },
  infoTitle: { color: '#B8D2F8', fontWeight: '800', marginBottom: 6 },
  infoText: { color: '#7F8DA2', lineHeight: 19 },
  securityHero: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#0E1723', borderRadius: 18, padding: 18, borderWidth: 1, borderColor: '#203048' },
  securityScore: { color: '#E7EDF6', fontSize: 22, fontWeight: '800' },
  checkRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#141D29' },
  checkIcon: { width: 30, height: 30, borderRadius: 15, backgroundColor: '#162238', color: '#A9CAFF', textAlign: 'center', textAlignVertical: 'center', fontWeight: '900', marginRight: 12 },
  checkStatus: { fontSize: 10, fontWeight: '900', letterSpacing: .5 },
  checkOk: { color: '#8ED4B1' },
  checkWarn: { color: '#F2C987' },
  aboutHero: { alignItems: 'center', paddingVertical: 14 },
  heroSmall: { color: '#F3F6FA', fontSize: 24, fontWeight: '800', letterSpacing: 3, marginTop: 10 },
  miniMeta: { color: '#65738A', fontSize: 11, textAlign: 'center', marginTop: 20 },
  dividerLabel: { color: '#677389', fontSize: 11, fontWeight: '800', letterSpacing: 1, marginTop: 28, marginBottom: 12 },
  toast: { position: 'absolute', left: 30, right: 30, bottom: 24, backgroundColor: '#EAF2FF', borderRadius: 14, paddingVertical: 13, alignItems: 'center' },
  toastText: { color: '#14243B', fontWeight: '800' },
  splash: { flex: 1, backgroundColor: '#070A10', alignItems: 'center', justifyContent: 'center' },
  splashIcon: { width: 122, height: 122, borderRadius: 30 },
  brandIcon: { width: 62, height: 62, borderRadius: 18 },
  brandIconLarge: { width: 110, height: 110, borderRadius: 28 },
  splashTitle: { color: '#F4F7FB', fontSize: 30, fontWeight: '900', letterSpacing: 5, marginTop: 18 },
  splashSub: { color: '#738095', marginTop: 6 },
  onboard: { flexGrow: 1, padding: 28, justifyContent: 'center' },
  hero: { color: '#F3F6FA', fontSize: 38, fontWeight: '800', lineHeight: 45, marginTop: 24 },
  heroAccent: { color: '#86B7FF' },
  onboardText: { color: '#7D899D', fontSize: 15, lineHeight: 23, marginTop: 15 },
  securityCard: { backgroundColor: '#0E1621', borderWidth: 1, borderColor: '#1D2B3E', borderRadius: 18, padding: 18, marginTop: 26 },
  cardTitle: { color: '#DDE8F7', fontWeight: '800' },
  cardText: { color: '#78869A', lineHeight: 19, marginTop: 6 },
  lock: { flex: 1, padding: 28, alignItems: 'center', justifyContent: 'center' },
  lockTitle: { color: '#F4F7FB', fontSize: 24, fontWeight: '800', marginTop: 24 },
  lockText: { color: '#7D899C', textAlign: 'center', lineHeight: 21, marginTop: 8, maxWidth: 320 },
});

