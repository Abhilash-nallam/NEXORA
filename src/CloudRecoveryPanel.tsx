import React, { useEffect, useState } from 'react';
import { Alert, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import {
  enableEncryptedCloudRecovery,
  getGoogleSession,
  hasLocalRecoveryEnabled,
  restoreEncryptedCloudVault,
  resumeGoogleSignInFromInitialUrl,
  signInWithGoogle,
  signOutGoogle,
  syncEncryptedCloudVault,
  type GoogleSession,
} from './cloudRecovery';

type Props = {
  vaultKey: Uint8Array;
  hasLocalEntries: boolean;
  onRestored: (key: Uint8Array) => Promise<void>;
  onToast: (message: string) => void;
};

export default function CloudRecoveryPanel({ vaultKey, hasLocalEntries, onRestored, onToast }: Props) {
  const [session, setSession] = useState<GoogleSession | null>(null);
  const [recoveryEnabled, setRecoveryEnabled] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState('');
  const [oneTimeCode, setOneTimeCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [showNewCode, setShowNewCode] = useState(false);
  const [status, setStatus] = useState('');

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const resumed = await resumeGoogleSignInFromInitialUrl();
        const [savedSession, enabled] = await Promise.all([
          resumed ? Promise.resolve(resumed) : getGoogleSession().catch(() => null),
          hasLocalRecoveryEnabled(),
        ]);
        if (active) {
          setSession(savedSession);
          setRecoveryEnabled(enabled);
        }
      } catch (error) {
        if (active) setStatus(error instanceof Error ? error.message : 'Google sign-in could not be resumed.');
      }
    })();
    return () => { active = false; };
  }, []);

  const runSignIn = async () => {
    setBusy(true);
    setStatus('');
    try {
      const next = await signInWithGoogle();
      setSession(next);
      setRecoveryEnabled(await hasLocalRecoveryEnabled());
      onToast('Google account connected');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Google sign-in failed.');
    } finally {
      setBusy(false);
    }
  };

  const runSignOut = async () => {
    setBusy(true);
    try {
      await signOutGoogle();
      setSession(null);
      setStatus('Signed out. Your local encrypted vault remains on this device.');
    } catch {
      setStatus('Could not sign out cleanly. Try again.');
    } finally {
      setBusy(false);
    }
  };

  const enableRecovery = async () => {
    setBusy(true);
    setStatus('');
    try {
      const code = await enableEncryptedCloudRecovery(vaultKey);
      setRecoveryEnabled(true);
      setOneTimeCode(code);
      setShowNewCode(true);
      onToast('Encrypted cloud recovery enabled');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Could not enable cloud recovery.');
    } finally {
      setBusy(false);
    }
  };

  const sync = async () => {
    setBusy(true);
    setStatus('');
    try {
      await syncEncryptedCloudVault();
      onToast('Encrypted vault synced');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Cloud sync failed.');
    } finally {
      setBusy(false);
    }
  };

  const restore = () => {
    const performRestore = async () => {
      setBusy(true);
      setStatus('');
      try {
        const recoveredKey = await restoreEncryptedCloudVault(recoveryCode);
        await onRestored(recoveredKey);
        setRecoveryCode('');
        onToast('Password vault restored');
      } catch (error) {
        setStatus(error instanceof Error ? error.message : 'Could not restore cloud vault.');
      } finally {
        setBusy(false);
      }
    };
    if (hasLocalEntries) {
      Alert.alert(
        'Replace this device’s password vault?',
        'Restoring replaces the current local password entries with the encrypted cloud snapshot. Export or sync any entries you need first.',
        [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Restore', style: 'destructive', onPress: () => void performRestore() },
        ],
      );
    } else {
      void performRestore();
    }
  };

  return (
    <View style={styles.card}>
      <Text style={styles.title}>Google account & recovery</Text>
      <Text style={styles.description}>
        Google verifies your identity. Your vault stays encrypted on your device before upload; the cloud receives ciphertext and a recovery-key-wrapped vault key.
      </Text>
      {session ? (
        <View style={styles.accountRow}>
          <View style={styles.accountCopy}>
            <Text style={styles.accountLabel}>Connected account</Text>
            <Text style={styles.email}>{session.user.email || 'Google account connected'}</Text>
          </View>
          <Pressable disabled={busy} onPress={() => void runSignOut()} style={styles.secondary}>
            <Text style={styles.secondaryText}>Sign out</Text>
          </Pressable>
        </View>
      ) : (
        <Pressable disabled={busy} onPress={() => void runSignIn()} style={styles.primary}>
          <Text style={styles.primaryText}>{busy ? 'Please wait…' : 'Continue with Google'}</Text>
        </Pressable>
      )}

      {session && !recoveryEnabled ? (
        <Pressable disabled={busy} onPress={() => void enableRecovery()} style={styles.primary}>
          <Text style={styles.primaryText}>{busy ? 'Please wait…' : 'Enable encrypted cloud recovery'}</Text>
        </Pressable>
      ) : null}

      {session && recoveryEnabled ? (
        <Pressable disabled={busy} onPress={() => void sync()} style={styles.secondaryWide}>
          <Text style={styles.secondaryText}>{busy ? 'Please wait…' : 'Sync encrypted vault now'}</Text>
        </Pressable>
      ) : null}

      {showNewCode ? (
        <View style={styles.recoveryBox}>
          <Text style={styles.recoveryTitle}>Save this recovery key now</Text>
          <Text style={styles.recoveryWarning}>It is shown only once. NEXORA does not store the recovery key itself. Anyone with this key and access to your Google account may recover your vault.</Text>
          <Text selectable style={styles.recoveryCode}>{oneTimeCode}</Text>
          <Pressable onPress={() => void Clipboard.setStringAsync(oneTimeCode).then(() => onToast('Recovery key copied'))} style={styles.secondaryWide}>
            <Text style={styles.secondaryText}>Copy recovery key</Text>
          </Pressable>
          <Pressable onPress={() => setShowNewCode(false)} style={styles.secondaryWide}>
            <Text style={styles.secondaryText}>I saved it</Text>
          </Pressable>
        </View>
      ) : null}

      {session ? (
        <View style={styles.restoreBox}>
          <Text style={styles.restoreTitle}>Restore on a new device</Text>
          <TextInput
            value={recoveryCode}
            onChangeText={setRecoveryCode}
            placeholder="Paste your 64-character recovery key"
            placeholderTextColor="#68738a"
            autoCapitalize="none"
            autoCorrect={false}
            spellCheck={false}
            secureTextEntry
            style={styles.input}
          />
          <Pressable disabled={busy || recoveryCode.trim().length === 0} onPress={restore} style={[styles.secondaryWide, (busy || !recoveryCode.trim()) && styles.disabled]}>
            <Text style={styles.secondaryText}>Restore encrypted vault</Text>
          </Pressable>
        </View>
      ) : null}

      {status ? <Text accessibilityRole="alert" style={styles.status}>{status}</Text> : null}
      <Text style={styles.footnote}>Cloud recovery needs the Supabase Google provider and the SQL migration configured. Keep your recovery key somewhere private and separate from your phone.</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { marginHorizontal: 16, marginBottom: 14, padding: 14, borderRadius: 16, backgroundColor: '#101b2d', borderWidth: 1, borderColor: '#26364e', gap: 10 },
  title: { color: '#f4f7ff', fontSize: 16, fontWeight: '700' },
  description: { color: '#aab7cc', fontSize: 12, lineHeight: 18 },
  accountRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 8 },
  accountCopy: { flex: 1 },
  accountLabel: { color: '#8293ad', fontSize: 11 },
  email: { color: '#e4edff', fontSize: 13, marginTop: 3 },
  primary: { backgroundColor: '#4c8dff', borderRadius: 10, paddingVertical: 11, paddingHorizontal: 12, alignItems: 'center' },
  primaryText: { color: '#fff', fontWeight: '700', fontSize: 13 },
  secondary: { borderWidth: 1, borderColor: '#3b4d68', borderRadius: 9, paddingVertical: 8, paddingHorizontal: 11 },
  secondaryWide: { borderWidth: 1, borderColor: '#3b4d68', borderRadius: 10, paddingVertical: 10, paddingHorizontal: 12, alignItems: 'center' },
  secondaryText: { color: '#dce7fb', fontWeight: '600', fontSize: 12 },
  recoveryBox: { borderWidth: 1, borderColor: '#6c5526', borderRadius: 12, padding: 12, gap: 8, backgroundColor: '#211d14' },
  recoveryTitle: { color: '#ffdf8d', fontSize: 14, fontWeight: '700' },
  recoveryWarning: { color: '#e6d8b4', fontSize: 12, lineHeight: 17 },
  recoveryCode: { color: '#fff3d1', fontSize: 13, lineHeight: 21, letterSpacing: 0.4 },
  restoreBox: { gap: 8, marginTop: 2 },
  restoreTitle: { color: '#e4edff', fontSize: 13, fontWeight: '700' },
  input: { backgroundColor: '#091322', borderWidth: 1, borderColor: '#2d405a', borderRadius: 10, padding: 11, color: '#f4f7ff', fontSize: 12 },
  disabled: { opacity: 0.45 },
  status: { color: '#ffbcab', fontSize: 12, lineHeight: 17 },
  footnote: { color: '#7f91aa', fontSize: 10, lineHeight: 15 },
});
