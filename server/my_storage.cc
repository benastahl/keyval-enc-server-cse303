#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/err.h"

#include "authtableentry.h"
#include "map.h"
#include "map_factories.h"
#include "persist.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  const string filename;

  /// The open file
  FILE *storage_file = nullptr;

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  MyStorage(const std::string &fname, size_t buckets)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {
    storage_file = nullptr;
  }

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    if (storage_file != nullptr) {
      fclose(storage_file);
      storage_file = nullptr;
    }
    delete auth_table;
    delete kv_store;
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    if (user.size() > (size_t)LEN_UNAME)
      return {false, RES_ERR_REQ_FMT, {}};

    vector<uint8_t> salt(LEN_SALT);
    if (RAND_bytes(salt.data(), LEN_SALT) != 1)
      return {false, RES_ERR_SERVER, {}};

    vector<uint8_t> pass_hash(SHA256_DIGEST_LENGTH);
    {
      vector<uint8_t> buf;
      buf.reserve(salt.size() + pass.size());
      buf.insert(buf.end(), salt.begin(), salt.end());
      buf.insert(buf.end(), reinterpret_cast<const uint8_t *>(pass.data()),
                 reinterpret_cast<const uint8_t *>(pass.data()) + pass.size());
      SHA256(buf.data(), buf.size(), pass_hash.data());
    }

    AuthTableEntry entry;
    entry.username = user;
    entry.salt = salt;
    entry.pass_hash = pass_hash;
    entry.content = {};

    bool inserted = auth_table->insert(
        user, entry, [&]() {
          if (storage_file)
            log_svv0(storage_file, AUTHENTRY, user, salt, pass_hash);
        });
    if (!inserted)
      return {false, RES_ERR_USER_EXISTS, {}};
    return {true, RES_OK, {}};
  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    bool user_found = false;
    bool pass_ok = false;
    user_found = auth_table->do_with(user, [&](AuthTableEntry &e) {
      vector<uint8_t> ph(SHA256_DIGEST_LENGTH);
      vector<uint8_t> buf;
      buf.reserve(e.salt.size() + pass.size());
      buf.insert(buf.end(), e.salt.begin(), e.salt.end());
      buf.insert(buf.end(), reinterpret_cast<const uint8_t *>(pass.data()),
                 reinterpret_cast<const uint8_t *>(pass.data()) + pass.size());
      SHA256(buf.data(), buf.size(), ph.data());
      if (ph == e.pass_hash) {
        pass_ok = true;
        e.content = content;
        if (storage_file)
          log_sv(storage_file, AUTHDIFF, user, content);
      }
    });
    if (!user_found || !pass_ok)
      return {false, RES_ERR_LOGIN, {}};
    return {true, RES_OK, {}};
  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    bool auth_ok = false;
    if (!auth_table->do_with_readonly(user, [&](const AuthTableEntry &e) {
          vector<uint8_t> ph(SHA256_DIGEST_LENGTH);
          vector<uint8_t> buf;
          buf.reserve(e.salt.size() + pass.size());
          buf.insert(buf.end(), e.salt.begin(), e.salt.end());
          buf.insert(buf.end(), reinterpret_cast<const uint8_t *>(pass.data()),
                     reinterpret_cast<const uint8_t *>(pass.data()) +
                         pass.size());
          SHA256(buf.data(), buf.size(), ph.data());
          auth_ok = (ph == e.pass_hash);
        }))
      return {false, RES_ERR_LOGIN, {}};
    if (!auth_ok)
      return {false, RES_ERR_LOGIN, {}};

    vector<uint8_t> out;
    bool found = auth_table->do_with_readonly(
        who, [&](const AuthTableEntry &e) { out = e.content; });
    if (!found)
      return {false, RES_ERR_NO_USER, {}};
    if (out.empty())
      return {false, RES_ERR_NO_DATA, {}};
    return {true, RES_OK, out};
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    bool auth_ok = false;
    if (!auth_table->do_with_readonly(user, [&](const AuthTableEntry &e) {
          vector<uint8_t> ph(SHA256_DIGEST_LENGTH);
          vector<uint8_t> buf;
          buf.reserve(e.salt.size() + pass.size());
          buf.insert(buf.end(), e.salt.begin(), e.salt.end());
          buf.insert(buf.end(), reinterpret_cast<const uint8_t *>(pass.data()),
                     reinterpret_cast<const uint8_t *>(pass.data()) +
                         pass.size());
          SHA256(buf.data(), buf.size(), ph.data());
          auth_ok = (ph == e.pass_hash);
        }))
      return {false, RES_ERR_LOGIN, {}};
    if (!auth_ok)
      return {false, RES_ERR_LOGIN, {}};

    string names;
    bool first = true;
    auth_table->do_all_readonly(
        [&](const string k, const AuthTableEntry &e) {
          (void)e;
          if (!first)
            names.push_back('\n');
          names += k;
          first = false;
        },
        []() {});
    vector<uint8_t> data(names.begin(), names.end());
    return {true, RES_OK, data};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    bool auth_ok = false;
    bool found = auth_table->do_with_readonly(user, [&](const AuthTableEntry &e) {
      vector<uint8_t> ph(SHA256_DIGEST_LENGTH);
      vector<uint8_t> buf;
      buf.reserve(e.salt.size() + pass.size());
      buf.insert(buf.end(), e.salt.begin(), e.salt.end());
      buf.insert(buf.end(), reinterpret_cast<const uint8_t *>(pass.data()),
                 reinterpret_cast<const uint8_t *>(pass.data()) + pass.size());
      SHA256(buf.data(), buf.size(), ph.data());
      auth_ok = (ph == e.pass_hash);
    });
    if (!found || !auth_ok)
      return {false, RES_ERR_LOGIN, {}};
    return {true, RES_OK, {}};
  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    auto a = auth(user, pass);
    if (!a.succeeded)
      return a;
    bool inserted = kv_store->insert(
        key, val, [&]() {
          if (storage_file)
            log_sv(storage_file, KVENTRY, key, val);
        });
    if (!inserted)
      return {false, RES_ERR_KEY, {}};
    return {true, RES_OK, {}};
  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {
    auto a = auth(user, pass);
    if (!a.succeeded)
      return a;
    vector<uint8_t> out;
    bool ok = kv_store->do_with_readonly(key, [&](const vector<uint8_t> &v) {
      out = v;
    });
    if (!ok)
      return {false, RES_ERR_KEY, {}};
    return {true, RES_OK, out};
  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {
    auto a = auth(user, pass);
    if (!a.succeeded)
      return a;
    bool removed = kv_store->remove(key, [&]() {
      if (storage_file)
        log_s(storage_file, KVDELETE, key);
    });
    if (!removed)
      return {false, RES_ERR_KEY, {}};
    return {true, RES_OK, {}};
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    auto a = auth(user, pass);
    if (!a.succeeded)
      return a;
    bool inserted = false;
    bool ok = kv_store->upsert(
        key, val,
        [&]() {
          inserted = true;
          if (storage_file)
            log_sv(storage_file, KVENTRY, key, val);
        },
        [&]() {
          if (storage_file)
            log_sv(storage_file, KVUPDATE, key, val);
        });
    (void)ok; // upsert always succeeds
    if (inserted)
      return {true, RES_OKINS, {}};
    return {true, RES_OKUPD, {}};
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    auto a = auth(user, pass);
    if (!a.succeeded)
      return a;
    string keys;
    bool first = true;
    kv_store->do_all_readonly(
        [&](const string k, const vector<uint8_t> &v) {
          (void)v;
          if (!first)
            keys.push_back('\n');
          keys += k;
          first = false;
        },
        []() {});
    vector<uint8_t> data(keys.begin(), keys.end());
    return {true, RES_OK, data};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    if (storage_file != nullptr) {
      fclose(storage_file);
      storage_file = nullptr;
    }
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    if (storage_file != nullptr) {
      fclose(storage_file);
      storage_file = nullptr;
    }

    string tmpname = filename + ".tmp";
    FILE *f = fopen(tmpname.c_str(), "wb");
    if (!f)
      return {false, RES_ERR_SERVER, {}};

    auto write_u32 = [](vector<uint8_t> &buf, uint32_t x) {
      uint8_t *p = reinterpret_cast<uint8_t *>(&x);
      buf.insert(buf.end(), p, p + sizeof(uint32_t));
    };

    bool ok = true;

    auth_table->do_all_readonly(
        [&](const string k, const AuthTableEntry &e) {
          vector<uint8_t> buf;
          buf.reserve(4 + 16 + e.username.size() + e.salt.size() +
                      e.pass_hash.size() + e.content.size() + 4);
          buf.insert(buf.end(), AUTHENTRY.begin(), AUTHENTRY.end());
          write_u32(buf, static_cast<uint32_t>(e.username.size()));
          write_u32(buf, static_cast<uint32_t>(e.salt.size()));
          write_u32(buf, static_cast<uint32_t>(e.pass_hash.size()));
          write_u32(buf, static_cast<uint32_t>(e.content.size()));
          buf.insert(buf.end(), e.username.begin(), e.username.end());
          buf.insert(buf.end(), e.salt.begin(), e.salt.end());
          buf.insert(buf.end(), e.pass_hash.begin(), e.pass_hash.end());
          buf.insert(buf.end(), e.content.begin(), e.content.end());
          size_t pad = (4 - (buf.size() % 4)) % 4;
          buf.insert(buf.end(), pad, 0);
          if (fwrite(buf.data(), 1, buf.size(), f) != buf.size())
            ok = false;
        },
        []() {});

    if (!ok) {
      fclose(f);
      return {false, RES_ERR_SERVER, {}};
    }

    kv_store->do_all_readonly(
        [&](const string k, const vector<uint8_t> &v) {
          vector<uint8_t> buf;
          buf.reserve(4 + 8 + k.size() + v.size() + 4);
          buf.insert(buf.end(), KVENTRY.begin(), KVENTRY.end());
          write_u32(buf, static_cast<uint32_t>(k.size()));
          write_u32(buf, static_cast<uint32_t>(v.size()));
          buf.insert(buf.end(), k.begin(), k.end());
          buf.insert(buf.end(), v.begin(), v.end());
          size_t pad = (4 - (buf.size() % 4)) % 4;
          buf.insert(buf.end(), pad, 0);
          if (fwrite(buf.data(), 1, buf.size(), f) != buf.size())
            ok = false;
        },
        []() {});

    if (!ok) {
      fclose(f);
      return {false, RES_ERR_SERVER, {}};
    }

    fflush(f);
    int fd = fileno(f);
    if (fd >= 0)
      fsync(fd);
    fclose(f);
    if (rename(tmpname.c_str(), filename.c_str()) != 0)
      return {false, RES_ERR_SERVER, {}};

    storage_file = fopen(filename.c_str(), "ab+");
    if (!storage_file)
      return {false, RES_ERR_SERVER, {}};
    fseek(storage_file, 0, SEEK_END);
    return {true, RES_OK, {}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    auth_table->clear();
    kv_store->clear();

    FILE *f = fopen(filename.c_str(), "rb");
    if (f == nullptr) {
      // open append-only for future logging
      storage_file = fopen(filename.c_str(), "ab+");
      if (storage_file)
        fseek(storage_file, 0, SEEK_END);
      return {true, "File not found: " + filename, {}};
    }

    auto read_exact = [](FILE *fp, void *dst, size_t n) -> bool {
      return fread(dst, 1, n, fp) == n;
    };

    auto read_u32 = [&](FILE *fp, uint32_t &x) -> bool {
      return read_exact(fp, &x, sizeof(uint32_t));
    };

    while (true) {
      char hdr[4];
      size_t got = fread(hdr, 1, 4, f);
      if (got == 0) {
        if (feof(f))
          break;
        fclose(f);
        return {false, RES_ERR_SERVER, {}};
      }
      if (got != 4) {
        fclose(f);
        return {false, RES_ERR_SERVER, {}};
      }
      string h(hdr, hdr + 4);

      auto skip_pad = [&](size_t base) {
        size_t pad = (4 - (base % 4)) % 4;
        if (pad) {
          uint8_t tmp[4];
          if (!read_exact(f, tmp, pad)) {
            return false;
          }
        }
        return true;
      };

      if (h == AUTHENTRY) {
        uint32_t lu = 0, ls = 0, lp = 0, lc = 0;
        if (!read_u32(f, lu) || !read_u32(f, ls) || !read_u32(f, lp) ||
            !read_u32(f, lc)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        vector<char> ub(lu);
        vector<uint8_t> sb(ls), pb(lp), cb(lc);
        if (!read_exact(f, ub.data(), lu) || !read_exact(f, sb.data(), ls) ||
            !read_exact(f, pb.data(), lp) || !read_exact(f, cb.data(), lc)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        AuthTableEntry e;
        e.username.assign(ub.begin(), ub.end());
        e.salt = std::move(sb);
        e.pass_hash = std::move(pb);
        e.content = std::move(cb);
        auth_table->upsert(e.username, e, []() {}, []() {});
        size_t consumed = 4 + 16 + lu + ls + lp + lc;
        if (!skip_pad(consumed)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
      } else if (h == KVENTRY) {
        uint32_t lk = 0, lv = 0;
        if (!read_u32(f, lk) || !read_u32(f, lv)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        vector<char> kb(lk);
        vector<uint8_t> vb(lv);
        if (!read_exact(f, kb.data(), lk) || !read_exact(f, vb.data(), lv)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        string k(kb.begin(), kb.end());
        kv_store->upsert(k, vb, []() {}, []() {});
        size_t consumed = 4 + 8 + lk + lv;
        if (!skip_pad(consumed)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
      } else if (h == AUTHDIFF) {
        uint32_t lu = 0, lc = 0;
        if (!read_u32(f, lu) || !read_u32(f, lc)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        vector<char> ub(lu);
        vector<uint8_t> cb(lc);
        if (!read_exact(f, ub.data(), lu) || !read_exact(f, cb.data(), lc)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        string uname(ub.begin(), ub.end());
        auth_table->do_with(uname, [&](AuthTableEntry &e) { e.content = cb; });
        size_t consumed = 4 + 8 + lu + lc;
        if (!skip_pad(consumed)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
      } else if (h == KVUPDATE) {
        uint32_t lk = 0, lv = 0;
        if (!read_u32(f, lk) || !read_u32(f, lv)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        vector<char> kb(lk);
        vector<uint8_t> vb(lv);
        if (!read_exact(f, kb.data(), lk) || !read_exact(f, vb.data(), lv)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        string k(kb.begin(), kb.end());
        kv_store->upsert(k, vb, []() {}, []() {});
        size_t consumed = 4 + 8 + lk + lv;
        if (!skip_pad(consumed)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
      } else if (h == KVDELETE) {
        uint32_t lk = 0;
        if (!read_u32(f, lk)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        vector<char> kb(lk);
        if (!read_exact(f, kb.data(), lk)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
        string k(kb.begin(), kb.end());
        kv_store->remove(k, []() {});
        size_t consumed = 4 + 4 + lk;
        if (!skip_pad(consumed)) {
          fclose(f);
          return {false, RES_ERR_SERVER, {}};
        }
      } else {
        fclose(f);
        return {false, RES_ERR_SERVER, {}};
      }
    }

    fclose(f);
    storage_file = fopen(filename.c_str(), "ab+");
    if (!storage_file)
      return {false, RES_ERR_SERVER, {}};
    fseek(storage_file, 0, SEEK_END);
    return {true, "Loaded: " + filename, {}};
  }
};

/// Create an empty Storage object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
Storage *storage_factory(const std::string &fname, size_t buckets) {
  return new MyStorage(fname, buckets);
}
