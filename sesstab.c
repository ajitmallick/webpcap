#include "webcap.h"

int sock_comp(struct entry *a, struct entry *b) {//Compares entry struct used for tree
	if ((!(a)) && (!(b))) return(-1);	//any one null return -1

	if (a->cli < b->cli) return(1);		//a is smaller than b return 1
	if (a->cli > b->cli) return(2);		//b is smaller than a return 2
	if (a->srv < b->srv) return(1);
	if (a->srv > b->srv) return(2);
	if (a->clip < b->clip) return(1);
	if (a->clip > b->clip) return(2);
	if (a->srvp < b->srvp) return(1);
	if (a->srvp > b->srvp) return(2);
	return(0);				//a is equal to b return 0
}

void insert(struct entry *tree, struct entry *new) {
	int res = (sock_comp(tree, new));
	if (res == 1) {				//new is smaller it goes left
		if (tree->left != NULL) {
			insert(tree->left, new);
		} else {
			tree->left = new;
			return;
		}
	}
	if (res == 2) {
		if (tree->right != NULL) {	//new is bigger it goes right
			insert(tree->right, new);
		} else {
			tree->right = new;
			return;
		}
	}
	if (res == 0) {
		if (tree->right != NULL) {	//new is equal it goes right
			tree->pipe++;		//pipe number incremented
			insert(tree->right, new);
		} else {
			tree->right = new;
			return;
		}
	}
}

/*search() finds occurance of entry in tree,*/
void search(struct entry *tree, struct entry *new, struct entry *last) {
	int res = (sock_comp(tree, new));
	if (res == 1) {
		if (tree->left != NULL) {
			search(tree->left, new, tree);
		} else {
			found = NULL;	
			parent = NULL;
			return;
		}
	}
	if (res == 2) {
		if (tree->right != NULL) {
			search(tree->right, new, tree);
		} else {
			found = NULL;	
			parent = NULL;
			return;
		}
	}
	if (res ==  0) {
		while (tree->pipe != 0) {
			parent = tree;
			tree = tree->right;
		}
		found = tree;		//matching entry
		parent = last;		//and its parent
		return;
	}
}

/*remove() removes entry*/
void move(struct entry *tree, struct entry *last) {
	if ((!(tree)) && (!(last))) return;
	if ( (!(tree->left)) && (!(tree->right)) ) {
		if (last->left == tree) {
			last->left = NULL;
			return;
		}
		if (last->right == tree) {
			last->right = NULL;
			return;
		}
	}
	if ( (tree->left) && (!(tree->right)) ) {
		if (last->left == tree) {
			last->left = tree->left;
			return;
		}
		if (last->right == tree) {
			last->right = tree->left;
			return;
		}
	}
	if ( (!(tree->left)) && (tree->right) ) {
		if (last->left == tree) {
			last->left = tree->right;
			return;
		}
		if (last->right == tree) {
			last->right = tree->right;
			return;
		}
	}
	if ( (tree->left) && (tree->right) ) {
		struct entry *next;
		if (last->left == tree) {
			last->left = tree->left;
			next = tree->left;
			while ( next->right != NULL ) {
				next = next->right;
			}
			next->right = tree->right;
			return;
		}
		if (last->right == tree) {
			last->right = tree->right;
			next = tree->right;
			while (next->left != NULL) {
				next = next->left;
			}
			next->left = tree->left;
			return;
		}
	}
}
