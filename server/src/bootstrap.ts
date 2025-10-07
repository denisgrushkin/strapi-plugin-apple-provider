import type { Core } from '@strapi/strapi';

const bootstrap = async ({ strapi }: { strapi: Core.Strapi }) => {
  try {
    const service = strapi
      .plugin('strapi-plugin-apple-provider')
      .service('service') as { registerProvider: () => Promise<void> };

    if (service?.registerProvider) {
      await service.registerProvider();
    }
  } catch (error) {
    strapi.log.error('[strapi-plugin-apple-provider] Failed to register Apple provider on bootstrap', error);
  }
};

export default bootstrap;
