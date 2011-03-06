#ifndef USER_HH
#define USER_HH

class user {

	public:

		unsigned int id;

		std::string username;
		std::string pwhash;
		std::string salt;

		unsigned int actions;
		bool visible;

		time_t last_action_at;
		time_t created_at;

		friendset_t friends;
		friendset_t friend_requests;

		// operators

		bool operator==(const user& ruser);
		bool operator!=(const user& ruser);
		bool operator=(const user& user);

		// constructors

		explicit user(const user& user);
		explicit user(const std::string& new_username, const std::string& new_password);
		explicit user(const std::string& serialized);

		bool set_username(const std::string& new_username);

		bool check_password(const std::string& try_password);
		bool set_password(const std::string& new_password);

		// update timestamps and other state

		void tick();

		// get status

		long idle();
		long age();
		double rate();
		bool is_online();
		bool has_friend(const user *user);
		bool has_friend(unsigned int id);
		int get_fd();

		// get neighbor distances

		nodelist_t& get_nodes();

      // serialization

      std::string serialize();

      // static

      static bool exists(const char *my_username);
      static bool exists(const std::string& my_username);

	private:

		nodelist_t nodes;

		// spanning tree and auxiliary functions

		void span_nodes(nodelist_t& todo, friendset_t& visited);
		void bfs(const node& root);
		void visit(node& current, nodelist_t& todo, friendset_t& visited);

		friendset_t getnumbers(std::stringstream& ss);
};

#endif
