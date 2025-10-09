import type { Core } from '@strapi/strapi';

const register = ({ strapi }: { strapi: Core.Strapi }) => {
  // Filter out the apple provider from the users-permissions providers list
  try {
    const settingsController = strapi
      .plugin('users-permissions')
      ?.controller('settings') as any;

    if (!settingsController) {
      return;
    }

    const originalGetProviders = settingsController.getProviders as
      | ((ctx: any, ...rest: any[]) => Promise<void>)
      | undefined;

    if (typeof originalGetProviders !== 'function') {
      return;
    }

    settingsController.getProviders = async function patchedGetProviders(ctx: any, ...args: any[]) {
      await originalGetProviders.call(this, ctx, ...args);

      const providers = ctx?.body;

      if (!providers || typeof providers !== 'object') {
        return;
      }

      if (Object.prototype.hasOwnProperty.call(providers, 'apple')) {
        const filteredProviders = { ...providers };
        delete filteredProviders.apple;
        ctx.body = filteredProviders;
      }
    };
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : typeof error === 'string' ? error : 'Unknown error';
    strapi.log.warn(`[strapi-plugin-apple-provider] Failed to patch users-permissions providers list: ${message}`);
  }
};

export default register;
