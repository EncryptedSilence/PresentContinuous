#include <vector>
#include <set>
#include<malloc.h>
using namespace std;

class stateval
{
	vector<set<vector<int>>> *val;
	int wordcount = 0;
public:
	stateval(int _wordcount)
	{
		val = new vector<set<vector<int>>>(_wordcount, set<vector<int>>());
		wordcount = _wordcount;
	}
	void fillrand(int d2count, int d1count)
	{
		for (int i = 0; i < val->size(); i++)
		{
			for (int j = 0; j < d2count; j++)
			{
				vector<int> coeffval;
				for (int k = 0; k < d1count; k++)
				{
					coeffval.push_back(rand() & 0xf);
				}
				set<vector<int>>* st = &val->at(i);
				st->insert(coeffval);
			}
		}
	}
	void printrev()
	{
		if (val == nullptr)
		{
			printf("NULL");
			return;
		}
		for (set<vector<int>> wordval : *val)
		{
			if (wordval.size() == 0)
				printf("NULL");
			for (vector<int> coeffval : wordval)
			{
				bool printed = false;
				int letter = 'a';
				printf("{");
				for (int c : coeffval)
				{
					if (c)
					{
						if (printed)
							printf(" + ");
						printed = true;
						if (c > 1)
							printf("%d*%c", c, letter);
						else
							printf("%c", letter);
					}
					letter++;
				}
				if (!printed)
					printf("NULL");
				printf("}, ");
			}
			printf("\n");
		}
	}
	void print()
	{
		if (val == nullptr)
		{
			printf("NULL");
			return;
		}
		for (set<vector<int>> wordval : *val)
		{
			if (wordval.size() == 0)
				printf("NULL");
			set<vector<int>>::reverse_iterator rit;
			for (rit = wordval.rbegin(); rit != wordval.rend(); ++rit)
			{
				vector<int> coeffval = *rit;
				bool printed = false;
				int letter = 'a';
				//printf("{");
				for (int c : coeffval)
				{
					if (c)
					{
						if (printed)
							printf(" + ");
						printed = true;
						if (c > 1)
							printf("%d%c", c, letter);
						else
							printf("%c", letter);
					}
					letter++;
				}
				if (!printed)
					printf("NULL");
				//printf("}, ");
				printf(", ");
			}
			printf("\n");
		}
	}
	void insert(vector<int>coeffval, int wordnum)
	{
		set<vector<int>>* st = &val->at(wordnum);
		st->insert(coeffval);
	}
	void add(vector<int>coeffval, int wordnum)
	{
		set<vector<int>>* st = &val->at(wordnum);
		set<vector<int>>::iterator iter = st->find(coeffval);
		if (iter == st->end())
			st->insert(coeffval);
		else
			st->erase(iter);
	}
	void incword(set<vector<int>>* st)
	{
		set<vector<int>>temp;
		
		for(set<vector<int>>::iterator iter = st->begin();iter!=st->end();iter++)
		{
			vector<int>v = *iter;
			v[0]++;
			temp.insert(v);
		}
		st->clear();
		for (vector<int> v : temp)
			st->insert(v);
	}
	void weirdmult()
	{
		for (int w = 0; w < wordcount; w++)	// number of word to change
		{
			set<vector<int>>* st = &val->at(w);
			incword(st);	// increment the word with 0-coefficient
			for (int s = 1; s < wordcount; s++)
			{
				int snum = (w + s) % wordcount;	// where to take val from
				for (vector<int> v : val->at(snum))
				{
					v[s]++;
					add(v, w);
				}
			}
			//printf("*------------------------------------------------*\nStage %d:\n", w);
			//print();
		}
	}
	void givenums(vector<int>coeffs, int modulo)
	{
		if (val == nullptr)
		{
			printf("NULL");
			return;
		}
		for (set<vector<int>> wordval : *val)
		{
			if (wordval.size() == 0)
				printf("NULL");
			set<vector<int>>::reverse_iterator rit;
			set<int>vals;
			for (rit = wordval.rbegin(); rit != wordval.rend(); ++rit)
			{
				vector<int> coeffval = *rit;
				int c = 0;
				for (int i=0;i<coeffval.size();i++)
				{
					c += coeffs[i] * coeffval[i];
				}
				c %= modulo;
				set<int>::iterator iter = vals.find(c);
				if (iter == vals.end())
					vals.insert(c);
				else
					vals.erase(iter);
			}
			bool printed = false;
			for (int v : vals)
			{
				if (printed)
					printf(", ");
				printed = true;
				printf("%d ", v);
			}
			printf("\n");
		}
	}
};

class multistateval
{
	vector<stateval*>* msv;
	int wordcount = 0;
public:
	multistateval(int _wordcount)
	{
		wordcount = _wordcount;
		msv = new vector<stateval*>();
		vector<int>coeffval0 = { 0,0,0,0 };
		for (int i = 0; i < wordcount; i++)
		{
			msv->push_back(new stateval(wordcount));
			msv->at(i)->insert(coeffval0, i);
			msv->at(i)->weirdmult();
		}
	}
	void print()
	{
		for (stateval *sv : *msv)
		{
			sv->print();
			printf("*------------------------------------------------*\n");
		}
	}
	void weirdmult()
	{
		for (int i = 0; i < wordcount; i++)
			msv->at(i)->weirdmult();
	}
	void givenums(vector<int>coeffs, int modulo)
	{
		printf("Relative numbers of active bits for { ");
		for (int x : coeffs)
			printf("%d ", x);
		printf("} is:\n");
		for (int i = 0; i < wordcount; i++)
		{
			msv->at(i)->givenums(coeffs, modulo);
			printf("*------------------------------------------------*\n");
		}
	}
};

void user_interface()
{
	int wordnum = 0, wordlen = 0, iters = 0;
	printf("Enter count of words:\n");
	scanf_s("%d", &wordnum);
	printf("Enter size of words:\n");
	scanf_s("%d", &wordlen);
	multistateval* msv = new multistateval(wordnum);
	vector<int>coeffs;
	printf("Enter %d coefficients (0..%d):\n", wordnum, wordlen - 1);
	for (int i = 0; i < wordnum; i++)
	{
		int tmp = 0;
		scanf_s("%d", &tmp);
		tmp %= wordlen;
		coeffs.push_back(tmp);
	}
	printf("Enter count of iterations:\n");
	scanf_s("%d", &iters);
	printf("Initial state (after 1 iteration):\n");
	msv->print();
	printf("*------------------------------------------------*\n");
	msv->givenums(coeffs, wordlen);
	printf("*------------------------------------------------*\n");
	for (int i = 1; i < iters; i++)
	{
		printf("State after %d iterations:\n", i + 1);
		msv->weirdmult();
		msv->print();
		printf("*------------------------------------------------*\n");
		msv->givenums(coeffs, wordlen);
		printf("*------------------------------------------------*\n");
	}
}

int main()
{
	user_interface();
}