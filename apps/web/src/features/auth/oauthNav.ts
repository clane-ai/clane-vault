/** Navigation seam (tests replace it): the consent answer carries a code, so it never goes through the router or query cache. */
export const oauthNav = { go: (url: string) => window.location.assign(url) };
