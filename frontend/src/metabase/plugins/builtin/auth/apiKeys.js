import { updateIn } from "icepick";

import { PLUGIN_ADMIN_SETTINGS_UPDATES } from "metabase/plugins";
import { ApiKeysAuthCard } from "metabase/admin/settings/auth/components/ApiKeysAuthCard";
import { ApiKeysList } from "metabase/admin/settings/components/ApiKeysList";

PLUGIN_ADMIN_SETTINGS_UPDATES.push(
  sections =>
    updateIn(sections, ["authentication", "settings"], settings => [
      ...settings,
      {
        key: "api-keys",
        description: null,
        noHeader: true,
        widget: ApiKeysAuthCard,
      },
    ]),
  sections => ({
    ...sections,
    "authentication/api-keys": {
      component: ApiKeysList,
      settings: [],
    },
  }),
);
