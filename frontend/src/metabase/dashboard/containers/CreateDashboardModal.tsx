import { useCallback } from "react";
import { t } from "ttag";
import { connect } from "react-redux";
import { push } from "connected-react-router";
import type { To } from "history";

import { CreateCollectionOnTheGo } from "metabase/containers/CreateCollectionOnTheGo";
import ModalContent from "metabase/components/ModalContent";

import * as Urls from "metabase/lib/urls";

import type { Dashboard } from "metabase-types/api";
import type { State } from "metabase-types/store";

import type { CreateDashboardFormOwnProps } from "./CreateDashboardForm";
import CreateDashboardForm from "./CreateDashboardForm";

interface CreateDashboardModalOwnProps
  extends Omit<CreateDashboardFormOwnProps, "onCancel"> {
  onClose?: () => void;
}

interface CreateDashboardModalDispatchProps {
  onChangeLocation: (location: To) => void;
}

type Props = CreateDashboardModalOwnProps & CreateDashboardModalDispatchProps;

const mapDispatchToProps = {
  onChangeLocation: push,
};

function CreateDashboardModal({
  onCreate,
  onChangeLocation,
  onClose,
  ...props
}: Props) {
  const handleCreate = useCallback(
    (dashboard: Dashboard) => {
      if (typeof onCreate === "function") {
        onCreate(dashboard);
      } else {
        onClose?.();
        onChangeLocation(Urls.dashboard(dashboard, { editMode: true }));
      }
    },
    [onCreate, onChangeLocation, onClose],
  );

  return (
    <CreateCollectionOnTheGo>
      {({ resumedValues }) => (
        <ModalContent title={t`New dashboard`} onClose={onClose}>
          <CreateDashboardForm
            {...props}
            onCreate={handleCreate}
            onCancel={onClose}
            initialValues={resumedValues}
          />
        </ModalContent>
      )}
    </CreateCollectionOnTheGo>
  );
}

// eslint-disable-next-line import/no-default-export -- deprecated usage
export default connect<
  unknown,
  CreateDashboardModalDispatchProps,
  CreateDashboardModalOwnProps,
  State
>(
  null,
  mapDispatchToProps,
)(CreateDashboardModal);
