import { Box, Button, Field, Flex, Loader, TextInput, Toggle, Typography } from '@strapi/design-system';
import { Layouts, useFetchClient, useNotification } from '@strapi/strapi/admin';
import { useEffect, useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import { useIntl } from 'react-intl';

import { getTranslation } from '../utils/getTranslation';

const API_PREFIX = '/strapi-plugin-apple-provider';

type PluginSettings = {
  redirectUrl: string;
  authKeyFilename: string | null;
  teamId: string;
  clientId: string;
  keyId: string;
  enabled: boolean;
  callbackUrl: string;
};

const HomePage = () => {
  const [redirectUrl, setRedirectUrl] = useState('');
  const [teamId, setTeamId] = useState('');
  const [clientId, setClientId] = useState('');
  const [keyId, setKeyId] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [callbackUrl, setCallbackUrl] = useState('');
  const [authKeyFile, setAuthKeyFile] = useState<File | null>(null);
  const [authKeyFilename, setAuthKeyFilename] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const fetchClient = useFetchClient();
  const toggleNotification = useNotification();
  const { formatMessage } = useIntl();

  const formatSettingsMessage = (
    id: string,
    defaultMessage: string,
    values?: Record<string, string | number>
  ) => formatMessage({ id: getTranslation(id), defaultMessage }, values);

  const loadSettings = async () => {
    try {
      const { data } = await fetchClient.get<PluginSettings>(`${API_PREFIX}/settings`);

      setRedirectUrl(data.redirectUrl ?? '');
      setTeamId(data.teamId ?? '');
      setClientId(data.clientId ?? '');
      setKeyId(data.keyId ?? '');
      setEnabled(Boolean(data.enabled));
      setAuthKeyFilename(data.authKeyFilename ?? null);
      setCallbackUrl(data.callbackUrl ?? '');
    } catch (error: any) {
      const message =
        error?.response?.data?.error?.message ??
        error?.message ??
        formatSettingsMessage('notifications.load-error', 'Failed to load settings');

      toggleNotification?.toggleNotification?.({
        type: 'danger',
        message,
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);

    const formData = new FormData();
    formData.append('redirectUrl', redirectUrl);
    formData.append('teamId', teamId);
    formData.append('clientId', clientId);
    formData.append('keyId', keyId);
    formData.append('enabled', String(enabled));
    if (authKeyFile) {
      formData.append('authKey', authKeyFile);
    }

    try {
      const { data } = await fetchClient.post<PluginSettings>(
        `${API_PREFIX}/settings`,
        formData
      );

      setRedirectUrl(data.redirectUrl ?? '');
      setTeamId(data.teamId ?? '');
      setClientId(data.clientId ?? '');
      setKeyId(data.keyId ?? '');
      setAuthKeyFilename(data.authKeyFilename ?? null);
      setAuthKeyFile(null);
      setCallbackUrl(data.callbackUrl ?? '');

      toggleNotification?.toggleNotification?.({
        type: 'success',
        message: formatSettingsMessage('notifications.save-success', 'Settings saved'),
      });
    } catch (error: any) {
      const message =
        error?.response?.data?.error?.message ??
        error?.message ??
        formatSettingsMessage('notifications.save-error', 'Failed to save settings');

      toggleNotification?.toggleNotification?.({
        type: 'danger',
        message,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setAuthKeyFile(file);
  };

  const { Root: RootLayout, Content: ContentLayout } = Layouts;

  if (isLoading) {
    return (
      <RootLayout>
        <ContentLayout>
          <Flex height="100%" justifyContent="center" alignItems="center" paddingTop={10}>
            <Loader />
          </Flex>
        </ContentLayout>
      </RootLayout>
    );
  }

  return (
    <RootLayout>
      <ContentLayout>
        <Typography as="h1" variant="alpha">
          {formatSettingsMessage('plugin.name', 'Apple Auth Provider')}
        </Typography>

        <Box paddingTop={6}>
          <Box as="form" onSubmit={handleSubmit}>
            <Box paddingBottom={6}>
              <Field.Root
                hint={formatSettingsMessage(
                  'settings.enabled.hint',
                  'Allow users to log in with Sign in with Apple once configuration is complete.'
                )}
                name="enabled"
              >
                <Field.Label>
                  {formatSettingsMessage('settings.enabled.label', 'Enable Sign in with Apple')}
                </Field.Label>
                <Toggle
                  aria-label="enabled"
                  checked={enabled}
                  offLabel={formatSettingsMessage('settings.toggle.off', 'Off')}
                  onLabel={formatSettingsMessage('settings.toggle.on', 'On')}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setEnabled(event.target.checked)}
                />
                <Field.Hint />
              </Field.Root>
            </Box>

            <Box paddingBottom={6}>
              <Typography as="label" htmlFor="clientId" variant="pi" fontWeight="bold">
                {formatSettingsMessage(
                  'settings.client-id.label',
                  'Client ID (Service ID)'
                )}
              </Typography>
              <Box paddingTop={2} paddingBottom={2}>
                <TextInput
                  id="clientId"
                  name="clientId"
                  placeholder="com.example.service"
                  value={clientId}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setClientId(event.target.value)}
                />
              </Box>
              <Typography variant="pi" textColor="neutral500">
                {formatSettingsMessage(
                  'settings.client-id.hint',
                  'The Service ID configured for Sign in with Apple.'
                )}
              </Typography>
            </Box>

            <Box paddingBottom={6}>
              <Typography as="label" htmlFor="teamId" variant="pi" fontWeight="bold">
                {formatSettingsMessage('settings.team-id.label', 'Team ID')}
              </Typography>
              <Box paddingTop={2} paddingBottom={2}>
                <TextInput
                  id="teamId"
                  name="teamId"
                  placeholder="XXXXXXXXXX"
                  value={teamId}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setTeamId(event.target.value)}
                />
              </Box>
              <Typography variant="pi" textColor="neutral500">
                {formatSettingsMessage(
                  'settings.team-id.hint',
                  'Find it in the top-right corner of your Apple Developer account.'
                )}
              </Typography>
            </Box>

            <Box paddingBottom={6}>
              <Typography as="label" htmlFor="keyId" variant="pi" fontWeight="bold">
                {formatSettingsMessage('settings.key-id.label', 'Key ID')}
              </Typography>
              <Box paddingTop={2} paddingBottom={2}>
                <TextInput
                  id="keyId"
                  name="keyId"
                  placeholder="XXXXXXXXXX"
                  value={keyId}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setKeyId(event.target.value)}
                />
              </Box>
              <Typography variant="pi" textColor="neutral500">
                {formatSettingsMessage(
                  'settings.key-id.hint',
                  'The identifier of the AuthKey used for generating the client secret.'
                )}
              </Typography>
            </Box>

            <Box paddingBottom={6}>
              <Typography as="label" htmlFor="redirectUrl" variant="pi" fontWeight="bold">
                {formatSettingsMessage(
                  'settings.redirect-url.label',
                  'The redirect URL to your front-end app'
                )}
              </Typography>
              <Box paddingTop={2} paddingBottom={2}>
                <TextInput
                  id="redirectUrl"
                  name="redirectUrl"
                  placeholder="https://your-app.example.com/auth/apple"
                  value={redirectUrl}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setRedirectUrl(event.target.value)}
                />
              </Box>
              <Typography variant="pi" textColor="neutral500">
                {formatSettingsMessage(
                  'settings.redirect-url.hint',
                  'Your users will be redirected to this URL with the Apple authorization code.'
                )}
              </Typography>
            </Box>

            <Box paddingBottom={6}>
              <Typography as="label" htmlFor="callbackUrl" variant="pi" fontWeight="bold">
                {formatSettingsMessage(
                  'settings.callback.label',
                  'Strapi callback URL'
                )}
              </Typography>
              <Box paddingTop={2} paddingBottom={2}>
                <TextInput id="callbackUrl" name="callbackUrl" value={callbackUrl} readOnly />
              </Box>
              <Typography variant="pi" textColor="neutral500">
                {formatSettingsMessage(
                  'settings.callback.hint',
                  'Add this URL to the Apple Developer console as an allowed return URL.'
                )}
              </Typography>
            </Box>

            <Box paddingBottom={6}>
              <Typography as="label" htmlFor="authKey" variant="pi" fontWeight="bold">
                {formatSettingsMessage(
                  'settings.auth-key.label',
                  'AuthKey_XXXXXXXXXX.p8 file'
                )}
              </Typography>
              <Box paddingTop={2} paddingBottom={2}>
                <input
                  id="authKey"
                  name="authKey"
                  type="file"
                  accept=".p8"
                  onChange={handleFileChange}
                />
              </Box>
              <Typography variant="pi" textColor="neutral500">
                {formatSettingsMessage(
                  'settings.auth-key.hint',
                  'Upload the private key downloaded from the Apple Developer portal.'
                )}
              </Typography>
              {authKeyFilename ? (
                <Typography variant="pi" textColor="neutral600">
                  {formatSettingsMessage('settings.auth-key.current', 'Current file: {file}', {
                    file: authKeyFilename,
                  })}
                </Typography>
              ) : (
                <Typography variant="pi" textColor="neutral600">
                  {formatSettingsMessage(
                    'settings.auth-key.none',
                    'No key has been uploaded yet.'
                  )}
                </Typography>
              )}
              {authKeyFile ? (
                <Typography variant="pi" textColor="neutral600">
                  {formatSettingsMessage('settings.auth-key.pending', 'Selected file: {file}', {
                    file: authKeyFile.name,
                  })}
                </Typography>
              ) : null}
            </Box>

            <Flex gap={2}>
              <Button type="submit" loading={isSubmitting}>
                {formatSettingsMessage('settings.save', 'Save')}
              </Button>
            </Flex>
          </Box>
        </Box>
      </ContentLayout>
    </RootLayout>
  );
};

export { HomePage };
