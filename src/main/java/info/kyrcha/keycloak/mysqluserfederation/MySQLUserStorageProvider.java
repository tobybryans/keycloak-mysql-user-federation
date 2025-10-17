/*
   Copyright 2020 Kyriakos Chatzidimitriou

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package info.kyrcha.keycloak.mysqluserfederation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.mindrot.jbcrypt.BCrypt;

public class MySQLUserStorageProvider
        implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, CredentialInputUpdater {

    protected KeycloakSession session;
    protected Connection conn;
    protected ComponentModel config;

    private static final Logger logger = Logger.getLogger(MySQLUserStorageProvider.class);

    public MySQLUserStorageProvider(KeycloakSession session, ComponentModel config, Connection conn) {
        this.session = session;
        this.config = config;
        this.conn = conn;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        UserModel adapter = null;
        try {
            String query = "SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=?;";
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            rs = pstmt.executeQuery();
            String pword = null;
            if (rs.next()) {
                pword = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            if (pword != null) {
                adapter = createAdapter(realm, username);
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }
        return adapter;
    }

    protected UserModel createAdapter(RealmModel realm, String username) {
        return new AbstractUserAdapter(session, realm, config) {
            @Override
            public String getUsername() {
                return username;
            }

	    @Override
            public SubjectCredentialManager credentialManager() {
                return new SubjectCredentialManager() {
                    @Override
                    public boolean isValid(List<CredentialInput> inputs) {
			// For read-only providers, this typically returns false
                        // since credential validation is handled elsewhere
                        return false;
                    }
        
                    @Override
                    public boolean updateCredential(CredentialInput input) {
                        return false; // Read-only provider
                    }
        
                    @Override
                    public void updateStoredCredential(CredentialModel cred) {
                        // Read-only provider - no-op
                    }
        
                    @Override
                    public CredentialModel createStoredCredential(CredentialModel cred) {
                        throw new UnsupportedOperationException("createStoredCredential not supported for read-only provider");
                    }
        
                    @Override
                    public boolean removeStoredCredentialById(String id) {
                        return false; // Read-only provider
                    }
        
                    @Override
                    public CredentialModel getStoredCredentialById(String id) {
                        return null; // No stored credentials in read-only provider
                    }
        
                    @Override
                    public Stream<CredentialModel> getStoredCredentialsStream() {
                        return Stream.empty(); // No stored credentials
                    }
        
                    @Override
                    public Stream<CredentialModel> getStoredCredentialsByTypeStream(String type) {
                        return Stream.empty(); // No stored credentials
                    }
        
                    @Override
                    public CredentialModel getStoredCredentialByNameAndType(String name, String type) {
                        return null; // No stored credentials
                    }
        
                    @Override
                    public boolean moveStoredCredentialTo(String id, String newPreviousCredentialId) {
                        return false; // Read-only provider
                    }
        
                    @Override
                    public void updateCredentialLabel(String credentialId, String credentialLabel) {
                        // Read-only provider - no-op
                    }
        
                    @Override
                    public void disableCredentialType(String credentialType) {
                        // Read-only provider - no-op
                    }
        
                    @Override
                    public Stream<String> getDisableableCredentialTypesStream() {
                        return Stream.empty();
                    }
        
                    @Override
                    public boolean isConfiguredFor(String type) {
                        return MySQLUserStorageProvider.this.supportsCredentialType(type);
                    }
        
                    @Override
                    public boolean isConfiguredLocally(String type) {
                        return false; // Deprecated, but still required
                    }
        
                    @Override
                    public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
                        return Stream.empty(); // Deprecated, but still required
                    }
        
                    @Override
                    public CredentialModel createCredentialThroughProvider(CredentialModel model) {
                        throw new UnsupportedOperationException("createCredentialThroughProvider not supported for read-only provider");
                    }
                };
            }
	};
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(realm, username);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return getUserByEmail( realm, email );
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        String password = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            String query = "SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=?;";
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, user.getUsername());
            rs = pstmt.executeQuery();
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }
        return credentialType.equals(CredentialModel.PASSWORD) && password != null;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(CredentialModel.PASSWORD);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()))
            return false;
        String password = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            String query = "SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=?;";
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, user.getUsername());
            rs = pstmt.executeQuery();
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (pstmt != null) {
                try {
                    pstmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                pstmt = null;
            }
        }

        if (password == null)
            return false;

        String hex = null;
        if (this.config.getConfig().getFirst("hash").equalsIgnoreCase("SHA1")) {
            hex = DigestUtils.sha1Hex(input.getChallengeResponse());
        } else if (this.config.getConfig().getFirst("hash").equalsIgnoreCase("MD5")) {
            hex = DigestUtils.md5Hex(input.getChallengeResponse());
        } else if (this.config.getConfig().getFirst("hash").equalsIgnoreCase("BCrypt")) {
	    // JBCrypt doesn't have a "hex" function, it's easier to get it to
	    // check the password and return here.
	    return BCrypt.checkpw( input.getChallengeResponse(), password );
	}
        return password.equalsIgnoreCase(hex);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (input.getType().equals(CredentialModel.PASSWORD))
            throw new ReadOnlyException("user is read only for this update");

        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {

    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream( RealmModel realm, UserModel user) {
	return Stream.empty();
    }

    @Override
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException sqlEx) {
                logger.error(sqlEx.getMessage());
            } // ignore
            conn = null;
        }
    }

}
