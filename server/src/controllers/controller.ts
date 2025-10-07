import type { Core } from '@strapi/strapi';

const controller = ({ strapi }: { strapi: Core.Strapi }) => ({
  callback(ctx) {
    ctx.body = strapi
      .plugin('strapi-plugin-apple-provider')
      // the name of the service file & the method.
      .service('service')
      .callback(ctx);
  },
});

export default controller;
