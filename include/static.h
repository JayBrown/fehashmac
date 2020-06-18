
static HashReturn Init( md6_state *state, 
		 int hashbitlen
		 );

static HashReturn Update( md6_state *state, 
		   const BitSequence *data, 
		   DataLength databitlen
		   );

static HashReturn Final( md6_state *state,
		  BitSequence *hashval
		  );

static HashReturn Hash( int hashbitlen,
		 const BitSequence *data,
		 DataLength databitlen,
		 BitSequence *hashval
		 );

