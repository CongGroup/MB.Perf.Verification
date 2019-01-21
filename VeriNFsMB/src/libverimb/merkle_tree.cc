#include "merkle_tree.h"
#include "veri_header.h"


using namespace std;



MerkleTree::MerkleTree()
{
	root = 0;
}

MerkleTree::~MerkleTree()
{
	if (root)
	{
		delete[] root;
	}
}

MerkleTree::MerkleTree(const uint32_t height_input, const std::vector<std::string>& data)
	:height(height_input)
{
	buildtree(height, data);
}

void MerkleTree::buildtree(const uint32_t height, const std::vector<std::string>& data)
{
	int hashCount = 0;

	//malloc tree space
	const int treeNodeCount = (1 << height) - 1;
	root = new TreeNode[treeNodeCount];
	for (int i = 1; i < treeNodeCount; i++)
	{
		root[i].parent = root + (i - 1) / 2;
	}

	// copy leavesLayer value
	const int leafLayerNodeCount = 1 << (height - 1);
	TreeNode* leavesLayer = root + leafLayerNodeCount - 1;
	auto iter = data.begin();
	for (int i = 0; i < leafLayerNodeCount; i++)
	{
		leavesLayer++->hashValue.assign(*iter++);
	}

	int currentLayer = height - 1;
	while (currentLayer != 0)
	{
		int baseIndex = (1 << (currentLayer - 1)) - 1;
		leavesLayer = root + baseIndex;
		for (int i = 0; i < (1 << (currentLayer - 1)); i++)
		{
			string value(root[(baseIndex + i) * 2].hashValue);
			value.append(root[(baseIndex + i) * 2 + 1].hashValue);
			leavesLayer->hashValue.assign(encTools::SHA256(value));
			hashCount += 1;
		}
		currentLayer -= 1;
	}
	//click_chatter("tree height is %d, tree node is %d", height, hashCount);
	
}

string MerkleTree::getRoot()
{
	return root->hashValue;
}

string MerkleTree::query(string leafHash)
{
	string res;
	//TreeNode* leavesLayer = root + (1 << (height - 1)) - 1;
	
	int loc;
	for (loc = (1 << (height - 1)) - 1; loc < (1 << height) - 1; loc++)
	{
		if (root[loc].hashValue == leafHash)
		{
			while (loc != 0)
			{
				if (loc % 2 == 0)
				{
					loc += 1;
				}
				else
				{
					loc -= 1;
				}

				res.append(root[loc].hashValue);
				loc = (loc - 1) / 2;
			}
			break;
		}
	}
	return res;
}

