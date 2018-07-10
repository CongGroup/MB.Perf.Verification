#ifndef MERKLETREE_H
#define MERKLETREE_H

#include <cstdint>
#include <string>
#include <vector>
class MerkleTree {
protected:
	struct TreeNode
	{
		TreeNode() :parent(0) {}

		TreeNode* parent;
		std::string hashValue;
	};

 public:
	 //height is tree height
	 //data is a array storage all leaves hash value
	 MerkleTree();
	 ~MerkleTree();
	 MerkleTree(const uint32_t height, const std::vector<std::string>& data);

	 void buildtree(const uint32_t height, const std::vector<std::string>& data);

	 std::string getRoot();
	 std::string query(std::string leafHash);

protected:
	TreeNode * root;
	uint32_t height;
};

#endif