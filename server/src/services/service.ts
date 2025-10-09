import path from 'node:path';
import { promises as fs } from 'node:fs';

import type { Core } from '@strapi/strapi';
import type { JwtPayload } from 'jsonwebtoken';
import jwt from 'jsonwebtoken';

type StoredSettings = {
  redirectUrl: string;
  authKeyFilename: string | null;
  teamId: string;
  clientId: string;
  keyId: string;
  enabled: boolean;
};

type PublicSettings = StoredSettings & {
  callbackUrl: string;
};

type SettingsInput = {
  redirectUrl?: unknown;
  authKey?: unknown;
  teamId?: unknown;
  clientId?: unknown;
  keyId?: unknown;
  enabled?: unknown;
};

type UploadedFile = {
  filepath: string;
  originalFilename?: string;
  newFilename?: string;
  mimetype?: string;
  size: number;
};

type AuthCallbackArgs = {
  accessToken?: string;
  query: Record<string, unknown>;
};

type SimpleFetchResponse = {
  ok: boolean;
  status: number;
  json: () => Promise<any>;
  text: () => Promise<string>;
};

type SimpleFetch = (input: string, init?: Record<string, unknown>) => Promise<SimpleFetchResponse>;

const SETTINGS_KEY = 'settings';
const APPLE_TOKEN_URL = 'https://appleid.apple.com/auth/token';
const APPLE_AUDIENCE = 'https://appleid.apple.com';
const APPLE_PROVIDER_NAME = 'apple';
const APPLE_REQUIRED_CUSTOM_PARAMS = {
  response_mode: 'form_post',
} as const;

const ensureErrorWithStatus = (message: string, status = 400) => {
  const error = new Error(message);
  // @ts-expect-error custom status used upstream
  error.status = status;
  return error;
};

const getDefaultSettings = (): StoredSettings => ({
  redirectUrl: '',
  authKeyFilename: null,
  teamId: '',
  clientId: '',
  keyId: '',
  enabled: false,
});

const normalizeSettings = (value: Partial<StoredSettings> | null | undefined): StoredSettings => ({
  redirectUrl: value?.redirectUrl ?? '',
  authKeyFilename: value?.authKeyFilename ?? null,
  teamId: value?.teamId ?? '',
  clientId: value?.clientId ?? '',
  keyId: value?.keyId ?? '',
  enabled:
    typeof value?.enabled === 'string'
      ? ['true', '1', 'on'].includes((value.enabled as string).toLowerCase())
      : Boolean(value?.enabled),
});

const isSettingsReady = (settings: StoredSettings) =>
  Boolean(
    settings.clientId && settings.teamId && settings.keyId && settings.authKeyFilename
  );

const service = ({ strapi }: { strapi: Core.Strapi }) => {
  const getPluginStore = () =>
    strapi.store({
      type: 'plugin',
      name: 'strapi-plugin-apple-provider',
      key: SETTINGS_KEY,
    });

  const getAppRoot = () => strapi.dirs?.app?.root ?? process.cwd();

  const getPublicServerUrl = () => {
    const configuredUrl =
      (strapi.config.get('server.url') as string | undefined) ??
      (strapi.config.get('server.publicUrl') as string | undefined) ??
      (strapi.config.get('server.absoluteUrl') as string | undefined);

    return configuredUrl ?? '';
  };

  const getCallbackUrl = () => {
    const baseUrl = getPublicServerUrl();

    if (!baseUrl) {
      return '';
    }

    try {
      const url = new URL(baseUrl);
      url.pathname = path.posix.join(url.pathname.replace(/\/+$/, ''), 'api', 'connect', APPLE_PROVIDER_NAME, 'callback');
      return url.toString();
    } catch (error) {
      strapi.log.warn(
        '[strapi-plugin-apple-provider] Failed to compute callback URL from server.url – please ensure PUBLIC_URL is set'
      );
      return '';
    }
  };

  const toPublicSettings = (settings: StoredSettings): PublicSettings => ({
    ...settings,
    callbackUrl: getCallbackUrl(),
  });

  const copyUploadedFile = async (fileInput: UploadedFile | UploadedFile[] | undefined | null) => {
    if (!fileInput) {
      return null;
    }

    const file = Array.isArray(fileInput) ? fileInput[0] : fileInput;

    if (!file) {
      return null;
    }

    const candidateName =
      file.originalFilename ?? file.newFilename ?? `AuthKey_${Date.now().toString(36)}.p8`;
    const safeFilename = path.basename(candidateName);

    if (!safeFilename.toLowerCase().endsWith('.p8')) {
      throw ensureErrorWithStatus('Uploaded file must have the .p8 extension.');
    }

    const destinationPath = path.join(getAppRoot(), safeFilename);
    await fs.copyFile(file.filepath, destinationPath);

    try {
      await fs.chmod(destinationPath, 0o600);
    } catch {
      // noop if chmod fails (e.g. on Windows)
    }

    try {
      await fs.unlink(file.filepath);
    } catch {
      // ignore temporary file cleanup issues
    }

    return safeFilename;
  };

  const removePreviousFile = async (filename: string | null | undefined, keepFilename: string) => {
    if (!filename || filename === keepFilename) {
      return;
    }

    const previousPath = path.join(getAppRoot(), filename);

    try {
      await fs.unlink(previousPath);
    } catch {
      // ignore missing file errors
    }
  };

  const validateRedirectUrl = (value: unknown) => {
    if (value === undefined || value === null || value === '') {
      return '';
    }

    if (typeof value !== 'string') {
      throw ensureErrorWithStatus('Redirect URL must be a string.');
    }

    const trimmed = value.trim();

    if (trimmed === '') {
      return '';
    }

    try {
      // eslint-disable-next-line no-new
      new URL(trimmed);
    } catch {
      throw ensureErrorWithStatus('Redirect URL must be a valid absolute URL.');
    }

    return trimmed;
  };

  const validateOptionalString = (value: unknown, fieldName: string) => {
    if (value === undefined) {
      return undefined;
    }

    if (value === null) {
      return '';
    }

    if (typeof value !== 'string') {
      throw ensureErrorWithStatus(`${fieldName} must be a string.`);
    }

    return value.trim();
  };

  const readPrivateKey = async (filename: string) => {
    const authKeyPath = path.join(getAppRoot(), filename);
    return fs.readFile(authKeyPath, 'utf8');
  };

  const generateClientSecret = async (settings: StoredSettings) => {
    if (!settings.authKeyFilename) {
      throw ensureErrorWithStatus('Auth key file has not been uploaded.');
    }

    const privateKey = await readPrivateKey(settings.authKeyFilename);
    const now = Math.floor(Date.now() / 1000);

    return jwt.sign(
      {
        iss: settings.teamId,
        iat: now,
        exp: now + 300,
        aud: APPLE_AUDIENCE,
        sub: settings.clientId,
      },
      privateKey,
      {
        algorithm: 'ES256',
        keyid: settings.keyId,
      }
    );
  };

  const exchangeAuthorizationCode = async (code: string, settings: StoredSettings) => {
    const fetchFn = globalThis.fetch as SimpleFetch | undefined;

    if (!fetchFn) {
      throw ensureErrorWithStatus('Global fetch API is not available in the current environment.', 500);
    }

    const clientSecret = await generateClientSecret(settings);
    const callbackUrl = getCallbackUrl();

    if (!callbackUrl) {
      throw ensureErrorWithStatus(
        'Unable to resolve the Apple callback URL. Please configure `PUBLIC_URL` in Strapi server settings.',
        500
      );
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUrl,
      client_id: settings.clientId,
      client_secret: clientSecret,
    });

    const response = await fetchFn(APPLE_TOKEN_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      strapi.log.warn(
        `[strapi-plugin-apple-provider] Apple token exchange failed with status ${response.status}: ${errorBody}`
      );
      throw ensureErrorWithStatus('Unable to exchange authorization code with Apple.');
    }

    return response.json();
  };

  const decodeIdentityToken = (token: string) => {
    const decoded = jwt.decode(token) as (JwtPayload & { email?: string }) | null;

    if (!decoded || typeof decoded === 'string') {
      throw ensureErrorWithStatus('Unable to decode Apple identity token.');
    }

    if (!decoded.sub) {
      throw ensureErrorWithStatus('Apple identity token does not include a subject.');
    }

    return decoded;
  };

  const syncGrantStore = async (settings: StoredSettings) => {
    const grantStore = strapi.store({
      type: 'plugin',
      name: 'users-permissions',
      key: 'grant',
    });

    const existingGrantConfig = ((await grantStore.get()) ?? {}) as Record<string, any>;
    const existingAppleConfig = existingGrantConfig[APPLE_PROVIDER_NAME] ?? {};

    const nextGrantConfig = {
      ...existingGrantConfig,
      [APPLE_PROVIDER_NAME]: {
        ...existingAppleConfig,
        enabled: settings.enabled && isSettingsReady(settings),
        key: settings.clientId,
        secret: existingAppleConfig.secret ?? '',
        callback: getCallbackUrl(),
        callbackUrl: getCallbackUrl(),
        scope: ['name', 'email'],
        custom_params: {
          ...(existingAppleConfig.custom_params ?? {}),
          ...APPLE_REQUIRED_CUSTOM_PARAMS,
        },
      },
    };

    await grantStore.set({ value: nextGrantConfig });
  };

  const syncProviderRegistration = async (settings: StoredSettings) => {
    const providersRegistry = strapi.service('plugin::users-permissions.providers-registry') as
      | {
          add: (
            name: string,
            config: {
              enabled: boolean;
              icon: string;
              grantConfig: Record<string, unknown>;
              authCallback: (args: AuthCallbackArgs) => Promise<Record<string, unknown>>;
            }
          ) => void;
        }
      | undefined;

    if (!providersRegistry?.add) {
      strapi.log.warn(
        '[strapi-plugin-apple-provider] Unable to register custom provider – providers registry not found.'
      );
      return;
    }

    providersRegistry.add(APPLE_PROVIDER_NAME, {
      enabled: settings.enabled && isSettingsReady(settings),
      icon: 'apple',
      grantConfig: {
        key: settings.clientId,
        callbackUrl: getCallbackUrl(),
        callback: getCallbackUrl(),
        scope: ['name', 'email'],
        custom_params: APPLE_REQUIRED_CUSTOM_PARAMS,
      },
      async authCallback({ accessToken, query }) {
        const pluginService = strapi
          .plugin('strapi-plugin-apple-provider')
          .service('service') as ReturnType<typeof service>;

        return pluginService.handleAuthCallback({
          accessToken,
          query,
        });
      },
    });
  };

  const findExistingAppleUserEmail = async (appleSub: string) => {
    const existingUser = await strapi.db.query('plugin::users-permissions.user').findOne({
      where: {
        provider: APPLE_PROVIDER_NAME,
        appleSub,
      },
    });

    return existingUser?.email ?? null;
  };

  return {
    async getSettings(): Promise<PublicSettings> {
      const pluginStore = getPluginStore();
      const storedValue = await pluginStore.get();

      if (!storedValue) {
        const defaults = getDefaultSettings();
        await pluginStore.set({ value: defaults });
        return toPublicSettings(defaults);
      }

      return toPublicSettings(normalizeSettings(storedValue));
    },

    async updateSettings({
      redirectUrl,
      authKey,
      teamId,
      clientId,
      keyId,
      enabled,
    }: SettingsInput): Promise<PublicSettings> {
      const pluginStore = getPluginStore();
      const currentSettings = normalizeSettings(await pluginStore.get());

      const nextRedirectUrl = validateRedirectUrl(redirectUrl);
      let nextAuthKeyFilename = currentSettings.authKeyFilename;

      if (authKey) {
        const newFilename = await copyUploadedFile(authKey as UploadedFile | UploadedFile[]);

        if (newFilename) {
          await removePreviousFile(currentSettings.authKeyFilename, newFilename);
          nextAuthKeyFilename = newFilename;
        }
      }

      const nextTeamId =
        validateOptionalString(teamId, 'Team ID') ?? currentSettings.teamId;
      const nextClientId =
        validateOptionalString(clientId, 'Client ID') ?? currentSettings.clientId;
      const nextKeyId =
        validateOptionalString(keyId, 'Key ID') ?? currentSettings.keyId;
      const nextEnabled =
        typeof enabled === 'undefined'
          ? currentSettings.enabled
          : ['true', '1', 'on', true].includes(
              typeof enabled === 'string' ? enabled.toLowerCase() : (enabled as boolean)
            );

      const mergedSettings: StoredSettings = {
        redirectUrl: nextRedirectUrl,
        authKeyFilename: nextAuthKeyFilename,
        teamId: nextTeamId,
        clientId: nextClientId,
        keyId: nextKeyId,
        enabled: nextEnabled,
      };

      await pluginStore.set({ value: mergedSettings });
      await syncProviderRegistration(mergedSettings);
      await syncGrantStore(mergedSettings);

      return toPublicSettings(mergedSettings);
    },

    async registerProvider() {
      const settings = await this.getSettings();
      await syncProviderRegistration(settings);
      await syncGrantStore(settings);
    },

    async handleAuthCallback({ accessToken, query }: AuthCallbackArgs) {
      const settings = await this.getSettings();

      if (!settings.enabled) {
        throw ensureErrorWithStatus('Apple provider is disabled.', 403);
      }

      if (!isSettingsReady(settings)) {
        throw ensureErrorWithStatus('Apple provider is not fully configured.', 500);
      }

      const authorizationCode =
        (typeof query.code === 'string' && query.code.trim()) ||
        (typeof accessToken === 'string' && accessToken.trim()) ||
        undefined;

      const identityTokenFromQuery =
        (typeof query.id_token === 'string' && query.id_token) ||
        (typeof query.identity_token === 'string' && query.identity_token) ||
        undefined;

      let idToken = identityTokenFromQuery ?? null;

      if (!idToken && authorizationCode) {
        const tokenResponse = await exchangeAuthorizationCode(authorizationCode, settings);
        if (!tokenResponse?.id_token) {
          throw ensureErrorWithStatus('Apple response did not include an identity token.');
        }
        idToken = tokenResponse.id_token;
      }

      if (!idToken) {
        throw ensureErrorWithStatus('Missing Apple identity token or authorization code.');
      }

      const decoded = decodeIdentityToken(idToken);
      const appleSub = decoded.sub;

      let email =
        (typeof decoded.email === 'string' && decoded.email) ||
        (typeof query.email === 'string' && query.email) ||
        null;

      if (!email) {
        email = await findExistingAppleUserEmail(appleSub);
      }

      if (!email) {
        throw ensureErrorWithStatus('Email was not provided by Apple.');
      }

      const normalizedEmail = email.toLowerCase();
      const username = normalizedEmail.split('@')[0] || appleSub;

      return {
        username,
        email: normalizedEmail,
        appleSub,
      };
    },

    async callback(ctx) {
      const codeFromRequest =
        (ctx.request.query?.code as string | undefined) ??
        (ctx.request.body?.code as string | undefined);

      if (!codeFromRequest) {
        ctx.throw(400, 'Missing authorization code.');
      }

      const settings = await this.getSettings();

      if (!settings.enabled) {
        ctx.throw(403, 'Apple provider is disabled.');
      }

      const redirectBase =
        settings.redirectUrl || (strapi.config.get('custom.siteBaseUrl') as string | undefined);

      if (!redirectBase) {
        ctx.throw(500, 'Redirect URL is not configured.');
      }

      const redirectUrlObject = new URL(redirectBase);
      redirectUrlObject.searchParams.set('code', codeFromRequest);

      ctx.redirect(redirectUrlObject.toString());
    },
  };
};

export default service;
