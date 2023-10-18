import type { Ref } from "react";
import { useLayoutEffect, useRef, useState } from "react";
import Tooltip from "metabase/core/components/Tooltip";
import type { TextProps, AnchorProps } from "metabase/ui";
import { Anchor, Text } from "metabase/ui";
import { ResultLink, ResultLinkWrapper } from "./SearchResultLink.styled";

export const SearchResultLink = ({
  children,
  leftIcon = null,
  href = null,
  ...textProps
}: {
  children: JSX.Element | string | null;
  leftIcon?: JSX.Element | null;
  href?: string | null;
} & (TextProps | AnchorProps)) => {
  const collectionRef: Ref<HTMLAnchorElement> = useRef(null);

  const [isOverflowing, setIsOverflowing] = useState(false);

  useLayoutEffect(() => {
    if (collectionRef.current) {
      setIsOverflowing(
        collectionRef.current.scrollWidth > collectionRef.current.clientWidth,
      );
    }
  }, [children]);

  const componentProps = href
    ? {
        as: Anchor,
        href,
        td: "underline",
      }
    : {
        as: Text,
        td: "none",
      };

  return (
    <Tooltip isEnabled={isOverflowing} tooltip={children}>
      <ResultLinkWrapper spacing={0}>
        {leftIcon}
        <ResultLink
          {...componentProps}
          span
          c="text.1"
          truncate
          onClick={e => e.stopPropagation()}
          ref={collectionRef}
          {...textProps}
        >
          {children}
        </ResultLink>
      </ResultLinkWrapper>
    </Tooltip>
  );
};
