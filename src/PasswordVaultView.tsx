import React, { useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator, Alert, FlatList, KeyboardAvoidingView, Platform, Pressable,
  ScrollView, StyleSheet, Text, TextInput, View,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
import * as Crypto from 'expo-crypto';
import { PasswordEntry, unlockPasswordVault, loadPasswordEntries, savePasswordEntries } from './passwordVault';
import CloudRecoveryPanel from './CloudRecoveryPanel';
import { getGoogleSession, hasLocalRecoveryEnabled, syncEncryptedCloudVault } from './cloudRecovery';

type Props = { onBack: () => void; onToast: (message: string) => void };

export default function PasswordVaultView({ onBack, onToast }: Props) {
  const [key, setKey] = useState<Uint8Array | null>(null);
  const [entries, setEntries] = useState<PasswordEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState<PasswordEntry | null>(null);
  const [title, setTitle] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [website, setWebsite] = useState('');
  const [category, setCategory] = useState('General');
  const [notes, setNotes] = useState('');
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [showForm, setShowForm] = useState(false);
  const clipboardTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const unlockedKey = await unlockPasswordVault();
        const saved = await loadPasswordEntries(unlockedKey);
        if (active) { setKey(unlockedKey); setEntries(saved); }
      } catch (error) {
        if (active) Alert.alert('Password vault locked', error instanceof Error ? error.message : 'Could not unlock vault.');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  const copySensitiveValue = async (value: string, label: string) => {
    try {
      await Clipboard.setStringAsync(value);
      if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);
      clipboardTimerRef.current = setTimeout(() => {
        void Clipboard.getStringAsync()
          .then((current) => current === value ? Clipboard.setStringAsync('') : undefined)
          .catch(() => undefined);
      }, 30_000);
      onToast(`${label} copied; clipboard clears in 30 seconds`);
    } catch {
      Alert.alert('Clipboard', `Could not copy ${label.toLowerCase()}.`);
    }
  };

  const resetForm = () => {
    setEditing(null); setTitle(''); setUsername(''); setPassword('');
    setWebsite(''); setCategory('General'); setNotes(''); setShowForm(false);
  };

  const persist = async (next: PasswordEntry[]) => {
    if (!key) throw new Error('Unlock the password vault first.');
    await savePasswordEntries(key, next);
    setEntries(next);
    try {
      if (await hasLocalRecoveryEnabled() && await getGoogleSession()) {
        await syncEncryptedCloudVault();
      }
    } catch {
      onToast('Saved locally; cloud sync failed.');
    }
  };

  const submit = async () => {
    try {
      const cleanTitle = title.trim();
      if (!cleanTitle || !password) { Alert.alert('Required fields', 'Enter a title and password.'); return; }
      const timestamp = Date.now();
      const item: PasswordEntry = {
        id: editing?.id || Crypto.randomUUID(), title: cleanTitle, username: username.trim(),
        password, website: website.trim(), category: category.trim() || 'General', notes,
        favorite: editing?.favorite || false, createdAt: editing?.createdAt || timestamp, updatedAt: timestamp,
      };
      const next = editing ? entries.map((entry) => entry.id === editing.id ? item : entry) : [item, ...entries];
      await persist(next);
      resetForm();
      onToast(editing ? 'Password updated' : 'Password saved securely');
    } catch (error) {
      Alert.alert('Could not save', error instanceof Error ? error.message : 'Try again.');
    }
  };

  const startEdit = (item: PasswordEntry) => {
    setEditing(item); setTitle(item.title); setUsername(item.username); setPassword(item.password);
    setWebsite(item.website); setCategory(item.category); setNotes(item.notes); setShowForm(true);
  };

  const remove = (item: PasswordEntry) => Alert.alert('Delete password?', 'Delete "' + item.title + '" from this device?', [
    { text: 'Cancel', style: 'cancel' },
    { text: 'Delete', style: 'destructive', onPress: () => void persist(entries.filter((entry) => entry.id !== item.id)).then(() => onToast('Password deleted')).catch(() => Alert.alert('Error', 'Could not delete entry.')) },
  ]);

  const filtered = entries.filter((entry) => (entry.title + ' ' + entry.username + ' ' + entry.website + ' ' + entry.category).toLowerCase().includes(query.toLowerCase()));

  const field = (label: string, value: string, change: (value: string) => void, placeholder: string, extra: any = {}) => (
    <View style={styles.field} key={label}>
      <Text style={styles.label}>{label}</Text>
      <TextInput value={value} onChangeText={change} placeholder={placeholder} placeholderTextColor="#68738a"
        autoCapitalize="none" style={[styles.input, extra.multiline && styles.multiline]} {...extra} />
    </View>
  );

  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Pressable onPress={onBack}><Text style={styles.action}>‹ Back</Text></Pressable>
        <Text style={styles.heading}>Password Vault</Text>
        <Pressable onPress={() => { resetForm(); setShowForm(true); }}><Text style={styles.action}>+ Add</Text></Pressable>
      </View>
      <View style={styles.searchArea}>
        <Text style={styles.hint}>Encrypted on this device • Biometric protected • No master password</Text>
        <TextInput value={query} onChangeText={setQuery} placeholder="Search passwords" placeholderTextColor="#68738a" style={styles.input} />
      </View>
      {showForm ? (
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
          <ScrollView contentContainerStyle={styles.form}>
            <Text style={styles.section}>{editing ? 'Edit password' : 'New password'}</Text>
            {field('Title *', title, setTitle, 'e.g. GitHub')}
            {field('Username / Email', username, setUsername, 'you@example.com', { keyboardType: 'email-address' })}
            {field('Password *', password, setPassword, 'Enter password', { secureTextEntry: true })}
            {field('Website', website, setWebsite, 'https://example.com', { keyboardType: 'url' })}
            {field('Category', category, setCategory, 'General, Work, Finance…')}
            {field('Notes', notes, setNotes, 'Optional secure notes', { multiline: true })}
            <Pressable style={styles.primary} onPress={() => void submit()}><Text style={styles.primaryText}>Save encrypted entry</Text></Pressable>
            <Pressable style={styles.secondary} onPress={resetForm}><Text style={styles.secondaryText}>Cancel</Text></Pressable>
          </ScrollView>
        </KeyboardAvoidingView>
      ) : loading ? <ActivityIndicator style={{ marginTop: 36 }} color="#91BFFF" /> : (
        <FlatList data={filtered} keyExtractor={(item) => item.id} contentContainerStyle={styles.list}
          ListHeaderComponent={key ? <CloudRecoveryPanel vaultKey={key} hasLocalEntries={entries.length > 0} onToast={onToast} onRestored={async (recoveredKey) => { const restored = await loadPasswordEntries(recoveredKey); setKey(recoveredKey); setEntries(restored); setRevealed({}); setShowForm(false); }} /> : null}
          ListEmptyComponent={<View style={styles.empty}><Text style={styles.title}>{entries.length ? 'No matching passwords' : 'Your password vault is empty'}</Text><Text style={styles.hint}>Save website logins here. Passwords are encrypted before being stored.</Text></View>}
          renderItem={({ item }) => (
            <View style={styles.card}>
              <View style={styles.cardTop}>
                <View style={styles.avatar}><Text style={styles.avatarText}>{item.title.slice(0, 1).toUpperCase()}</Text></View>
                <View style={{ flex: 1 }}><Text style={styles.title}>{item.title}</Text><Text style={styles.hint}>{item.username || item.website || item.category}</Text></View>
                <Pressable onPress={() => setRevealed((prev) => ({ ...prev, [item.id]: !prev[item.id] }))}><Text style={styles.action}>{revealed[item.id] ? 'Hide' : 'Show'}</Text></Pressable>
              </View>
              <Text style={styles.password} selectable={false}>{revealed[item.id] ? item.password : '••••••••••••'}</Text>
              {!!item.website && <Text style={styles.hint}>{item.website}</Text>}
              <View style={styles.actions}>
                <Pressable style={styles.small} onPress={() => void copySensitiveValue(item.password, 'Password')}><Text style={styles.smallText}>Copy password</Text></Pressable>
                <Pressable style={styles.small} onPress={() => startEdit(item)}><Text style={styles.smallText}>Edit</Text></Pressable>
                <Pressable style={styles.small} onPress={() => remove(item)}><Text style={[styles.smallText, { color: '#F49A9A' }]}>Delete</Text></Pressable>
              </View>
            </View>
          )}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#070A10' },
  header: { minHeight: 58, paddingHorizontal: 18, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', borderBottomWidth: 1, borderBottomColor: '#1B2635' },
  heading: { color: '#F4F7FB', fontSize: 17, fontWeight: '800' },
  action: { color: '#91BFFF', fontWeight: '700', fontSize: 14 },
  searchArea: { paddingHorizontal: 18, paddingTop: 12, gap: 8 },
  hint: { color: '#8794A8', fontSize: 12, lineHeight: 18 },
  input: { backgroundColor: '#101722', borderWidth: 1, borderColor: '#263447', borderRadius: 12, minHeight: 46, color: '#F4F7FB', paddingHorizontal: 12, paddingVertical: 10 },
  form: { padding: 18, gap: 12, paddingBottom: 40 },
  section: { color: '#AFCFFF', fontSize: 12, fontWeight: '800', letterSpacing: 1, textTransform: 'uppercase' },
  field: { gap: 6 },
  label: { color: '#C3CDDB', fontSize: 13, fontWeight: '700' },
  multiline: { minHeight: 90, textAlignVertical: 'top' },
  primary: { backgroundColor: '#77AFFF', borderRadius: 12, padding: 15, alignItems: 'center', marginTop: 4 },
  primaryText: { color: '#08111F', fontWeight: '800' },
  secondary: { borderWidth: 1, borderColor: '#2A394D', borderRadius: 12, padding: 14, alignItems: 'center' },
  secondaryText: { color: '#D6E1F0', fontWeight: '700' },
  list: { padding: 18, gap: 12, paddingBottom: 40 },
  card: { backgroundColor: '#101620', borderRadius: 16, padding: 15, borderWidth: 1, borderColor: '#1B2635' },
  cardTop: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  avatar: { width: 42, height: 42, borderRadius: 13, backgroundColor: '#1D2B40', alignItems: 'center', justifyContent: 'center' },
  avatarText: { color: '#A9CAFF', fontWeight: '800', fontSize: 17 },
  title: { color: '#F4F7FB', fontSize: 15, fontWeight: '800' },
  password: { color: '#D6E1F0', fontSize: 15, marginTop: 14, marginBottom: 5 },
  actions: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, marginTop: 13 },
  small: { borderRadius: 9, backgroundColor: '#1A2636', paddingVertical: 8, paddingHorizontal: 10 },
  smallText: { color: '#D6E1F0', fontSize: 12, fontWeight: '700' },
  empty: { padding: 24, alignItems: 'center', gap: 8 },
});
