import type { Ref } from "react";
import { useMemo } from "react";
import { push } from "react-router-redux";
import { t } from "ttag";
import type { IconName } from "metabase/core/components/Icon";
import { getTranslatedEntityName } from "metabase/common/utils/model-names";
import { useListKeyboardNavigation } from "metabase/hooks/use-list-keyboard-navigation";
import * as Urls from "metabase/lib/urls";
import { SearchLoadingSpinner } from "metabase/nav/components/search/SearchResults/SearchResults";
import { SearchResultLink } from "metabase/search/components/SearchResultLink";
import type { RecentItem, UnrestrictedLinkEntity } from "metabase-types/api";
import { useRecentItemListQuery } from "metabase/common/hooks";
import RecentItems from "metabase/entities/recent-items";
import { useDispatch } from "metabase/lib/redux";
import { isSyncCompleted } from "metabase/lib/syncing";
import { ItemIcon } from "metabase/search/components/SearchResult";
import {
  LoadingSection,
  ModerationIcon,
  ResultNameSection,
  ResultTitle,
  SearchResultContainer,
} from "metabase/search/components/SearchResult/SearchResult.styled";
import { Group, Loader, Stack, Title, Paper } from "metabase/ui";

type RecentsListProps = {
  onClick?: (elem: UnrestrictedLinkEntity) => void;
  className?: string;
};

interface WrappedRecentItem extends RecentItem {
  getUrl: () => string;
  getIcon: () => {
    name: IconName;
    size?: number;
    width?: number;
    height?: number;
  };
}

export const RecentsList = ({ onClick, className }: RecentsListProps) => {
  const { data = [], isLoading: isRecentsListLoading } = useRecentItemListQuery(
    {
      reload: true,
    },
  );

  const wrappedResults: WrappedRecentItem[] = useMemo(
    () => data.map(item => RecentItems.wrapEntity(item)),
    [data],
  );

  const dispatch = useDispatch();

  const { getRef, cursorIndex } = useListKeyboardNavigation<
    RecentItem,
    HTMLButtonElement
  >({
    list: wrappedResults,
    onEnter: (item: RecentItem) => onChangeLocation(item),
  });

  const onChangeLocation = (item: RecentItem) => {
    const url = getItemUrl(item);
    if (url) {
      dispatch(push(url));
    }
  };

  const onContainerClick = (item: RecentItem) => {
    if (onClick) {
      onClick({
        ...item.model_object,
        model: item.model,
        name: item.model_object.display_name ?? item.model_object.name,
        id: item.model_id,
      });
    } else {
      onChangeLocation(item);
    }
  };

  return (
    <Paper withBorder className={className}>
      {isRecentsListLoading ? (
        <SearchLoadingSpinner />
      ) : (
        <Stack spacing="md" px="sm" py="md">
          <Title order={4} px="sm">{t`Recently viewed`}</Title>
          <Stack spacing={0}>
            {wrappedResults.map((item, index) => {
              const isActive = isItemActive(item);
              const model = item.model;
              const name = getItemName(item);
              const moderated_status = getModeratedStatus(item);
              const result = item;
              const isSelected = cursorIndex === index;
              const ref: Ref<HTMLButtonElement> = getRef(item) ?? null;

              return (
                <SearchResultContainer
                  ref={ref}
                  key={getItemKey(item)}
                  component="button"
                  onClick={() => onContainerClick(item)}
                  isActive={isActive}
                  isSelected={isSelected}
                  p="sm"
                >
                  <ItemIcon active={isActive} item={result} type={model} />
                  <ResultNameSection justify="center" spacing="xs">
                    <Group spacing="xs" align="center" noWrap>
                      <ResultTitle order={4} truncate>
                        {name}
                      </ResultTitle>
                      <ModerationIcon status={moderated_status} size={14} />
                    </Group>
                    <SearchResultLink size="sm" c="text.1">
                      {getTranslatedEntityName(item.model)}
                    </SearchResultLink>
                  </ResultNameSection>
                  {isItemLoading(item) && (
                    <LoadingSection px="xs">
                      <Loader />
                    </LoadingSection>
                  )}
                </SearchResultContainer>
              );
            })}
          </Stack>
        </Stack>
      )}
    </Paper>
  );
};

const getItemKey = ({
  model,
  model_id,
}: Pick<RecentItem, "model_id" | "model">) => {
  return `${model}:${model_id}`;
};

const getItemName = ({ model_object }: Pick<RecentItem, "model_object">) => {
  return model_object.display_name || model_object.name;
};

const getModeratedStatus = ({
  model_object,
}: Pick<RecentItem, "model_object">) => {
  return model_object.moderated_status;
};

const isItemActive = ({
  model,
  model_object,
}: Pick<RecentItem, "model_object" | "model">) => {
  switch (model) {
    case "table":
      return isSyncCompleted(model_object);
    default:
      return true;
  }
};

const isItemLoading = ({
  model,
  model_object,
}: Pick<RecentItem, "model_object" | "model">) => {
  switch (model) {
    case "table":
      return !isSyncCompleted(model_object);
    default:
      return false;
  }
};

const getItemUrl = (item: RecentItem) =>
  isItemActive(item) ? Urls.modelToUrl(item) : "";
