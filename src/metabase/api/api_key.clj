(ns metabase.api.api-key
  "/api/api-key endpoints for CRUD management of API Keys"
  (:require
   [compojure.core :refer [POST]]
   [crypto.random :as crypto-random]
   [metabase.api.common :as api]
   [metabase.models.api-key :as api-key]
   [metabase.models.permissions-group :as perms-group]
   [metabase.models.user :as user]
   [metabase.util :as u]
   [metabase.util.honey-sql-2 :as h2x]
   [metabase.util.malli.schema :as ms]
   [toucan2.core :as t2]))


(def ^:private user-first-name "API Key:")

(defn- full-name [n]
  (str user-first-name " " n))

(defn- count-api-key-users-with-name [n]
  (:count
   (t2/query-one {:select [[[:count :core_user.id] :count]]
                  :from :core_user
                  :where [:= (h2x/concat :first_name (h2x/literal " ") :last_name) (full-name n)]})))

(defn- key-with-unique-prefix []
  (u/auto-retry 5
   (let [api-key (api-key/generate-key)
         prefix (api-key/prefix api-key)]
     ;; we could make this more efficient by generating 5 API keys up front and doing one select to remove any
     ;; duplicates. But a duplicate should be rare enough to just do multiple queries for now.
     (if-not (t2/exists? :model/ApiKey :key_prefix prefix)
       api-key
       (throw (ex-info "could not generate key with unique prefix" {}))))))

(api/defendpoint POST "/"
  "Create a new API key (and an associated `User`) with the provided name and group ID."
  [:as {{:keys [group_id name] :as _body} :body}]
  {group_id ms/PositiveInt
   name     ms/NonBlankString}
  (let [api-key (key-with-unique-prefix)
        prefix  (api-key/prefix api-key)
        email   (format "api-key-user-%s@api-key.invalid" name)]
    (api/check-superuser)
    (api/checkp (not (t2/exists? :model/User :%lower.email email))
      "name" "An API key with this name already exists.")
    (t2/with-transaction [_conn]
      (let [user (first (t2/insert-returning-instances! :model/User
                                                        {:email      email
                                                         :password   (crypto-random/base64 16)
                                                         :first_name "API Key:"
                                                         :last_name  name
                                                         :type       :api-key}))]
        (user/set-permissions-groups! user [(perms-group/all-users) {:id group_id}])
        (u/prog1 (-> (t2/insert-returning-instances! :model/ApiKey
                                                     {:user_id    (u/the-id user)
                                                      :key        api-key
                                                      :key_prefix prefix
                                                      :created_by api/*current-user-id*})
                     (select-keys [:created_at :updated_at :id])
                     (assoc :name name
                            :group_id group_id
                            :unmasked_key api-key
                            :masked_key (api-key/mask api-key)))
          ;; There is no restriction in the database that full names
          ;; are unique, so we insert the user first, then check that
          ;; there is only one user with that name before committing.
          ;; Theoretically, there is still a race condition - two
          ;; requests to create an API key with the same name at the
          ;; same time could both get committed at once - but I think
          ;; the odds/severity are low enough that we can accept it.
          (api/check-400 (= 1 (count-api-key-users-with-name name))))))))

(api/define-routes)
