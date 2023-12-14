import { entityForObject } from "metabase/lib/schema";

export const getIcon = (item: any) => {
  const entity = entityForObject(item);
  return entity?.objectSelectors?.getIcon?.(item)?.name || "table";
};
